# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""server-run probes for net devices.

plain values in, no django, caller stores results.
"""

import asyncio
import datetime as dt
import re
import secrets
import socket
import ssl
import struct
import time
from contextlib import suppress
from ipaddress import IPv4Address, ip_address

# The Celery workers have no CAP_NET_RAW, ping brings its own file capability.
PING = "/usr/bin/ping"
PING_ARGS = ("-n", "-q", "-c", "3", "-i", "0.2", "-W", "1", "-w", "3")
PING_TIMEOUT = 6
TCP_TIMEOUT = 2
SNMP_TIMEOUT = 2
SNMP_RETRIES = 1
CONCURRENCY = 16
# a poll run stops waiting after this, unfinished devices are due again
DEADLINE = 45

SYS_NAME = "1.3.6.1.2.1.1.5.0"
SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
SYS_DESCR = "1.3.6.1.2.1.1.1.0"
IF_ADMIN = "1.3.6.1.2.1.2.2.1.7."
IF_OPER = "1.3.6.1.2.1.2.2.1.8."
# one GETBULK, larger devices are counted partly
IF_ROWS = 64
# Printer-MIB prtMarkerSuppliesTable: description, max capacity, level
PRT_DESCR = "1.3.6.1.2.1.43.11.1.1.6."
PRT_MAX = "1.3.6.1.2.1.43.11.1.1.8."
PRT_LEVEL = "1.3.6.1.2.1.43.11.1.1.9."
# prtMarkerLifeCount of the first marker
PRT_PAGES = "1.3.6.1.2.1.43.10.2.1.4.1.1"
PRT_ROWS = 16

# HTTP(S) and DNS monitors, one timeout for all of it
MONITOR_TIMEOUT = 5
MAX_MONITORS = 8
# the response head is buffered up to this, the body is never read
HEAD_LIMIT = 16384
USER_AGENT = "ULRMM-netmon"
DNS_PORT = 53
QTYPES = {"A": 1, "AAAA": 28}
RCODES = {1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}

_LABEL_RE = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")
PATH_RE = re.compile(r"/[!-~]{0,255}")
STATUS_RE = re.compile(
    r"[1-5][0-9]{2}(-[1-5][0-9]{2})?(,[1-5][0-9]{2}(-[1-5][0-9]{2})?){0,7}"
)
_STATUS_LINE_RE = re.compile(rb"HTTP/1\.[01] ([1-5][0-9]{2})[ \r]")

AUTH_PROTOCOLS = {
    "sha": "usmHMACSHAAuthProtocol",
    "sha224": "usmHMAC128SHA224AuthProtocol",
    "sha256": "usmHMAC192SHA256AuthProtocol",
    "sha384": "usmHMAC256SHA384AuthProtocol",
    "sha512": "usmHMAC384SHA512AuthProtocol",
}

_RTT_RE = re.compile(r"= [\d.]+/([\d.]+)/")


class ProbeError(Exception):
    pass


def address_error(host: str, networks, own, own_allowed=False) -> str:
    """Why the server must not probe host, empty if it may.
    networks: IPv4Networks it may reach, own: its own addresses,
    own_allowed: own_ok() of the target."""
    try:
        ip = IPv4Address(host)
    except ValueError:
        return "Enter an IPv4 address."
    if ip in own and not (own_allowed and not ip.is_loopback):
        return (
            "That is an address of the server itself. It only takes HTTPS"
            " monitors on port 443 with path /, to watch its own certificate."
        )
    if (
        ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return "Loopback, link-local, multicast and reserved addresses are not probed."
    for net in networks:
        if ip in net:
            if net.prefixlen < 31 and ip in (
                net.network_address,
                net.broadcast_address,
            ):
                return f"That is the network or broadcast address of {net}."
            return ""
    allowed = ", ".join(str(n) for n in sorted(networks)) or "none"
    return f"The server only probes its own networks ({allowed})."


def own_ok(target: dict) -> bool:
    """Whether target may go to the server's own address: HTTPS monitors on
    443 with path / and nothing else."""
    monitors = target["monitors"]
    return (
        bool(monitors)
        and not (target["ping"] or target["tcp_ports"] or target["snmp"])
        and all(
            m["type"] == "http"
            and m["scheme"] == "https"
            and m["port"] == 443
            and m["path"] == "/"
            for m in monitors
        )
    )


def clean(value, limit: int) -> str:
    return "".join(c for c in str(value) if c.isprintable())[:limit]


def is_hostname(name: str) -> bool:
    """A DNS name, lower case, never a URL, port, user or address."""
    labels = name.split(".")
    return (
        len(name) <= 253
        and all(_LABEL_RE.fullmatch(label) for label in labels)
        and not labels[-1].isdigit()
    )


def status_ranges(spec: str) -> list[tuple[int, int]]:
    """Parses a spec that matches STATUS_RE, "200-399,401" gives
    [(200, 399), (401, 401)]."""
    ranges = []
    for part in spec.split(","):
        low, _, high = part.partition("-")
        ranges.append((int(low), int(high or low)))
    return ranges


def monitor_label(m: dict) -> str:
    if m["type"] == "dns":
        return f"DNS {m['record']} {m['query']}"
    name = f"{m['server_name']}:" if m["server_name"] else ""
    return f"{m['scheme'].upper()} {name}{m['port']}{m['path']}"


async def ping(host: str) -> tuple[bool, float | None]:
    """(replied, average rtt in ms). ProbeError if ping itself failed."""
    try:
        proc = await asyncio.create_subprocess_exec(
            PING,
            *PING_ARGS,
            host,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            env={"LC_ALL": "C"},
        )
    except OSError as e:
        raise ProbeError(f"{PING} does not run: {e.strerror}")
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), PING_TIMEOUT)
    except BaseException:
        with suppress(ProcessLookupError):
            proc.kill()
        raise
    # 1 is no reply, anything else is ping failing
    if proc.returncode == 1:
        return False, None
    if proc.returncode != 0:
        raise ProbeError(f"{PING} exited with {proc.returncode}")
    m = _RTT_RE.search(out.decode(errors="replace"))
    return True, float(m.group(1)) if m else None


async def tcp_open(host: str, port: int) -> bool:
    """Connects and closes again, sends nothing."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), TCP_TIMEOUT
        )
    except (OSError, TimeoutError):
        return False
    writer.close()
    with suppress(Exception):
        await asyncio.wait_for(writer.wait_closed(), 1)
    return True


def if_counts(varbinds) -> tuple[int, int]:
    """(up, down) of the interfaces that are administratively up."""
    admin, oper = {}, {}
    for oid, value in varbinds:
        for prefix, table in ((IF_ADMIN, admin), (IF_OPER, oper)):
            if oid.startswith(prefix):
                table[oid[len(prefix) :]] = value
    wanted = [i for i, v in admin.items() if v == 1 and i in oper]
    up = sum(oper[i] == 1 for i in wanted)
    return up, len(wanted) - up


def _int(value) -> int | None:
    with suppress(Exception):
        return int(value)
    return None


def printer_supplies(varbinds) -> list[dict]:
    """[{name, level, max, percent}] per supply. Negative levels and
    capacities are Printer-MIB "other", "unknown" or "some left", percent
    stays None then."""
    rows = {}
    for oid, value in varbinds:
        for prefix, key in (
            (PRT_DESCR, "name"),
            (PRT_MAX, "max"),
            (PRT_LEVEL, "level"),
        ):
            if oid.startswith(prefix):
                rows.setdefault(oid[len(prefix) :], {})[key] = value
    supplies = []
    for row in rows.values():
        if "name" not in row:
            continue
        level, top = _int(row.get("level")), _int(row.get("max"))
        percent = None
        if level is not None and top and top > 0 and level >= 0:
            percent = min(round(level * 100 / top), 100)
        supplies.append(
            {
                "name": clean(row["name"], 64),
                "level": level,
                "max": top,
                "percent": percent,
            }
        )
    return supplies[:PRT_ROWS]


def printer_check(m: dict, printer) -> dict:
    """A printer monitor: warning when a supply is at or under the threshold.
    Marks those supplies with "low"."""
    supplies = (printer or {}).get("supplies") or []
    known = [s for s in supplies if s["percent"] is not None]
    for s in supplies:
        s["low"] = s["percent"] is not None and s["percent"] <= m["threshold"]
    low = [f"{s['name']} {s['percent']}%" for s in supplies if s["low"]]
    if not known:
        status, message = "error", "no supply levels over SNMP (Printer-MIB)"
    else:
        status, message = ("warning", "low: " + ", ".join(low)) if low else ("ok", "")
    return {
        "status": status,
        "message": clean(message, 300),
        "label": "Printer supplies",
    }


async def snmp_poll(
    host: str,
    port: int,
    version: str,
    secret: dict,
    user="",
    auth_proto="sha256",
    printer=False,
) -> dict:
    """GET and GETBULK of fixed OIDs only. The secret stays in this process."""
    import pysnmp.hlapi.v3arch.asyncio as h

    if version == "v2c":
        auth = h.CommunityData(secret["community"], mpModel=1)
    else:
        auth = h.UsmUserData(
            user,
            secret["auth_key"],
            secret["priv_key"],
            authProtocol=getattr(h, AUTH_PROTOCOLS[auth_proto]),
            privProtocol=h.usmAesCfb128Protocol,
        )
    engine = h.SnmpEngine()
    try:
        target = await h.UdpTransportTarget.create(
            (host, port), timeout=SNMP_TIMEOUT, retries=SNMP_RETRIES
        )
        oids = (SYS_NAME, SYS_UPTIME, SYS_DESCR)
        err, status, _, binds = await h.get_cmd(
            engine,
            auth,
            target,
            h.ContextData(),
            *(h.ObjectType(h.ObjectIdentity(o)) for o in oids),
            lookupMib=False,
        )
        if err or status:
            raise ProbeError(clean(err or status.prettyPrint(), 200))
        name, uptime, descr = (v for _, v in binds)
        ticks = _int(uptime)
        result = {
            "sys_name": clean(name, 64),
            "sys_uptime": ticks // 100 if ticks is not None else None,
            "sys_descr": clean(descr, 255),
        }
        err, status, _, binds = await h.bulk_cmd(
            engine,
            auth,
            target,
            h.ContextData(),
            0,
            IF_ROWS,
            h.ObjectType(h.ObjectIdentity(IF_ADMIN[:-1])),
            h.ObjectType(h.ObjectIdentity(IF_OPER[:-1])),
            lookupMib=False,
        )
        if not (err or status):
            up, down = if_counts((str(n), _int(v)) for n, v in binds)
            result.update(if_up=up, if_down=down)
        if printer:
            result["printer"] = await printer_poll(h, engine, auth, target)
        return result
    finally:
        engine.close_dispatcher()


async def printer_poll(h, engine, auth, target) -> dict:
    err, status, _, binds = await h.bulk_cmd(
        engine,
        auth,
        target,
        h.ContextData(),
        0,
        PRT_ROWS,
        *(
            h.ObjectType(h.ObjectIdentity(c[:-1]))
            for c in (PRT_DESCR, PRT_MAX, PRT_LEVEL)
        ),
        lookupMib=False,
    )
    supplies = [] if err or status else printer_supplies((str(n), v) for n, v in binds)
    err, status, _, binds = await h.get_cmd(
        engine,
        auth,
        target,
        h.ContextData(),
        h.ObjectType(h.ObjectIdentity(PRT_PAGES)),
        lookupMib=False,
    )
    pages = None if err or status else _int(binds[0][1])
    return {"supplies": supplies, "pages": pages}


def name_matches(name: str, patterns) -> bool:
    """A wildcard only stands for the whole left-most label."""
    rest = name.partition(".")[2]
    for pattern in patterns:
        pattern = str(pattern).lower().rstrip(".")
        if pattern == name or (rest and pattern == "*." + rest):
            return True
    return False


def cert_info(der: bytes, server_name: str = "") -> dict:
    """With a server name, "name_ok" says whether the certificate is for it,
    for when nothing else checked the name."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    cert = x509.load_der_x509_certificate(der)

    def cn(name):
        attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        return clean(", ".join(str(a.value) for a in attrs), 128)

    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        names = san.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        names = []
    not_after = cert.not_valid_after_utc
    info = {
        "days_left": (not_after - dt.datetime.now(dt.timezone.utc)).days,
        "not_after": not_after.isoformat(),
        "issuer": cn(cert.issuer),
        "subject": cn(cert.subject),
        "names": [clean(n, 128) for n in names[:5]],
    }
    if server_name:
        # the common name only counts without DNS names
        attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        info["name_ok"] = name_matches(server_name, names or [a.value for a in attrs])
    return info


def _unverified() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def http_check(host: str, m: dict) -> dict:
    """One request to host, never anywhere else: the server name only goes
    into SNI, the certificate check and the Host header. Redirects are
    reported, not followed, and the body is never read."""
    name = m["server_name"]
    if (
        (name and not is_hostname(name))
        or not PATH_RE.fullmatch(m["path"])
        or m["method"] not in ("GET", "HEAD")
    ):
        raise ProbeError("invalid monitor")
    host, port = str(IPv4Address(host)), m["port"]
    ctx, problem = None, ""
    if m["scheme"] == "https":
        if m["allow_self_signed"]:
            ctx = _unverified()
        else:
            ctx = ssl.create_default_context()
            # the device address is rarely in its certificate
            ctx.check_hostname = bool(name)

    def connect():
        return asyncio.open_connection(
            host,
            port,
            ssl=ctx,
            server_hostname=(name or host) if ctx else None,
            limit=HEAD_LIMIT,
        )

    start = time.monotonic()
    try:
        reader, writer = await connect()
    except ssl.SSLCertVerificationError as e:
        # not trusted, read it anyway for the dates
        problem = "certificate: " + clean(e.verify_message or e, 150)
        ctx = _unverified()
        reader, writer = await connect()
    host_header = name or host
    if port != (443 if ctx else 80):
        host_header += f":{port}"
    try:
        writer.write(
            f"{m['method']} {m['path']} HTTP/1.1\r\nHost: {host_header}\r\n"
            f"User-Agent: {USER_AGENT}\r\nConnection: close\r\n\r\n".encode()
        )
        try:
            head = await reader.readuntil(b"\r\n\r\n")
        except asyncio.LimitOverrunError:
            raise ProbeError(f"response head over {HEAD_LIMIT} bytes")
        except asyncio.IncompleteReadError:
            raise ProbeError("connection closed before a response")
        der = ctx and writer.get_extra_info("ssl_object").getpeercert(True)
    finally:
        writer.close()
        with suppress(Exception):
            await asyncio.wait_for(writer.wait_closed(), 1)
    ms = round((time.monotonic() - start) * 1000, 1)

    match = _STATUS_LINE_RE.match(head)
    if not match:
        raise ProbeError("not an HTTP/1 response")
    code = int(match.group(1))
    errors, warning, cert = [], "", None
    if not any(low <= code <= high for low, high in status_ranges(m["status"])):
        errors.append(f"HTTP {code}")
    if problem:
        errors.append(problem)
    if der:
        try:
            # without verification the name was not checked either
            cert = cert_info(der, name if m["allow_self_signed"] else "")
        except Exception:
            errors.append("unreadable certificate")
        else:
            if not cert.get("name_ok", True):
                errors.append(f"certificate is not for {name}")
            cert["verified"] = not (problem or m["allow_self_signed"])
            days = cert["days_left"]
            if days < m["error_days"] and not problem:
                errors.append(
                    f"certificate expired {-days} days ago"
                    if days < 0
                    else f"certificate expires in {days} days"
                )
            elif days < m["warn_days"]:
                warning = f"certificate expires in {days} days"
    return {
        "status": "error" if errors else "warning" if warning else "ok",
        "message": "; ".join(errors) or warning,
        "code": code,
        "ms": ms,
        "cert": cert,
    }


def dns_question(name: str, qtype: int) -> bytes:
    labels = name.encode("ascii").split(b".")
    qname = b"".join(bytes([len(label)]) + label for label in labels)
    return qname + b"\0" + struct.pack("!HH", qtype, 1)


def _skip_name(data: bytes, pos: int) -> int:
    """Past a name. Pointers are never followed, so a pointer loop cannot
    loop here; IndexError when the packet ends early."""
    while (size := data[pos]) != 0:
        if size >= 0xC0:
            return pos + 2
        if size > 63:
            raise ValueError("bad label")
        pos += size + 1
    return pos + 1


def dns_answers(data: bytes, qid: int, question: bytes, qtype: int):
    """(rcode, addresses of qtype) from a response, None if it does not
    answer this query. A matching but broken one raises ValueError,
    IndexError or struct.error."""
    end = 12 + len(question)
    if len(data) < end:
        return None
    rid, flags, qdcount, ancount = struct.unpack_from("!4H", data)
    # QR set, opcode 0, the question echoed
    if (
        rid != qid
        or flags & 0xF800 != 0x8000
        or qdcount != 1
        or data[12:end].lower() != question
    ):
        return None
    size = 4 if qtype == 1 else 16
    pos, found = end, []
    for _ in range(ancount):
        pos = _skip_name(data, pos)
        rtype, rclass, _, length = struct.unpack_from("!HHIH", data, pos)
        pos += 10
        rdata = data[pos : pos + length]
        if len(rdata) != length:
            raise ValueError("record past the end")
        pos += length
        if rtype == qtype and rclass == 1 and length == size:
            found.append(str(ip_address(rdata)))
    return flags & 0xF, found


async def dns_check(host: str, m: dict) -> dict:
    """One query over UDP to host itself. Replies with another ID, flags or
    question are ignored until the timeout."""
    if not is_hostname(m["query"]) or m["record"] not in QTYPES:
        raise ProbeError("invalid monitor")
    qtype = QTYPES[m["record"]]
    question = dns_question(m["query"], qtype)
    qid = secrets.randbelow(0x10000)
    loop = asyncio.get_running_loop()
    start = time.monotonic()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setblocking(False)
        # connected, so the kernel drops datagrams from any other address,
        # and picks a random source port
        sock.connect((str(IPv4Address(host)), DNS_PORT))
        await loop.sock_sendall(
            sock, struct.pack("!6H", qid, 0x0100, 1, 0, 0, 0) + question
        )
        answer = None
        while answer is None:
            data = await loop.sock_recv(sock, 4096)
            try:
                answer = dns_answers(data, qid, question, qtype)
            except (ValueError, IndexError, struct.error):
                raise ProbeError("malformed DNS response")
    ms = round((time.monotonic() - start) * 1000, 1)

    rcode, found = answer
    if rcode:
        error = f"DNS {RCODES.get(rcode, rcode)}"
    elif not found:
        error = f"no {m['record']} record"
    elif m["expect"] and set(found) != set(m["expect"]):
        error = f"answered {', '.join(found[:8])}, expected {', '.join(m['expect'])}"
    else:
        error = ""
    return {
        "status": "error" if error else "ok",
        "message": clean(error, 300),
        "answers": found[:8],
        "ms": ms,
    }


async def run_monitor(host: str, m: dict) -> dict:
    check = dns_check if m["type"] == "dns" else http_check
    try:
        result = await asyncio.wait_for(check(host, m), MONITOR_TIMEOUT)
    except TimeoutError:
        result = {"status": "error", "message": "timed out"}
    except Exception as e:
        result = {"status": "error", "message": clean(e, 200) or type(e).__name__}
    result["label"] = clean(monitor_label(m), 300)
    return result


def status_of(target: dict, result: dict) -> str:
    if result["error"]:
        return "error"
    checks = list(result["ports"].values())
    if target["snmp"]:
        checks.append("error" not in result["snmp"])
    # a monitor warning is degraded, but still an answer
    monitors = result.get("monitors") or []
    checks += [m["status"] != "error" for m in monitors]
    if target["ping"]:
        if not result["ping"]:
            return "down"
    elif not any(checks):
        return "down"
    if all(checks) and all(m["status"] == "ok" for m in monitors):
        return "up"
    return "degraded"


async def probe(target: dict) -> dict:
    """target: host, ping, tcp_ports, snmp (None or snmp_poll's keyword
    arguments without host), monitors (optional)."""
    host = target["host"]
    monitors = target.get("monitors") or []
    checks = [m for m in monitors if m["type"] != "printer"]
    printers = [m for m in monitors if m["type"] == "printer"]
    result = {
        "ping": None,
        "rtt_ms": None,
        "ports": {},
        "snmp": None,
        "monitors": [],
        "error": "",
    }

    async def do_ping():
        try:
            result["ping"], result["rtt_ms"] = await ping(host)
        except (ProbeError, TimeoutError) as e:
            result["error"] = clean(e, 200) or "ping timed out"

    async def do_tcp(port):
        result["ports"][str(port)] = await tcp_open(host, port)

    async def do_snmp():
        try:
            result["snmp"] = await snmp_poll(
                host, **target["snmp"], printer=bool(printers)
            )
        except Exception as e:
            error = str(e)
            for value in target["snmp"]["secret"].values():
                error = error.replace(value, "********")
            result["snmp"] = {"error": clean(error, 200) or type(e).__name__}

    async def do_monitors():
        jobs = (run_monitor(host, m) for m in checks)
        result["monitors"] = list(await asyncio.gather(*jobs))

    jobs = [do_tcp(p) for p in target["tcp_ports"]]
    if checks:
        jobs.append(do_monitors())
    if target["ping"]:
        jobs.append(do_ping())
    if target["snmp"]:
        jobs.append(do_snmp())
    await asyncio.gather(*jobs)
    if printers:
        result["printer"] = (result["snmp"] or {}).pop("printer", None)
        result["monitors"] += [printer_check(m, result["printer"]) for m in printers]
    result["status"] = status_of(target, result)
    return result


async def probe_all(targets: list, deadline: float = DEADLINE) -> list:
    """Results in the order of targets, None where the deadline hit first."""
    if not targets:
        return []
    sem = asyncio.Semaphore(CONCURRENCY)

    async def one(target):
        async with sem:
            return await probe(target)

    tasks = [asyncio.ensure_future(one(t)) for t in targets]
    done, pending = await asyncio.wait(tasks, timeout=deadline)
    for task in pending:
        task.cancel()
    await asyncio.gather(*pending, return_exceptions=True)
    return [t.result() if t in done and not t.exception() else None for t in tasks]
