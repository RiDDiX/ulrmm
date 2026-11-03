"""Golden runs of the agents, alerts/checks/tasks and core inventories.

They use the item schema of base.py plus these keys:

  <area>.prelude   python run once per class after the fixture loaded (next to the
                   items); its rows, users and tokens are there for every item
  after            ids of items this one builds on: they run first in its test
  capture          {"name": "<sql>"}: the first value becomes {{VAR:name}};
                   shell lines "PARITY_VAR <name> <value>" do the same
  cleanup          python run after the item (matters when another item chains it)
  post             python run after the item; what it prints is part of the answer
  nats_agents      agent pks whose NATS requests get canned answers; every other
                   subject has no responder
  repeat           send the request N times ("vary_headers" formats {i}); the answer
                   holds the statuses
  settings         settings overridden while the item runs
  method WS        sockets and steps in "ws", run in-process against the ASGI app
  compare.sql      queries whose rows are recorded as psql -At -F "|" prints them, sorted
  compare.effects  tables whose row changes ("<table>"), row counts ("count:<table>")
                   and the queued celery tasks ("celery") are recorded
  unordered "id"   only lists of objects with an "id" are compared as sets

NATS is a stand-in (connect works, nobody answers unless asked to), names resolve
only from the class's hosts and sockets reach loopback only, so nothing leaves the
test.
"""

import asyncio
import base64
import contextlib
import datetime as dt
import hashlib
import http.server
import ipaddress
import io
import json
import os
import re
import shlex
import socket
import socketserver
import sys
import tempfile
import threading
import unittest
from unittest import mock

import msgpack
import time_machine
from django.core.cache import cache
from django.core.management.commands import shell as shell_command
from django.db import connection, connections, transaction
from django.test import override_settings

from ulrmm.golden import base

CASE = None  # the running test, for the helpers below
# a private address the URL action items reach on port 8080 (served in-process)
LAN_IP = "10.98.76.54"
# generated task names, jitter and timings, generated command ids
MASKS = [
    r"(?<=ULRMM_)[A-Za-z]{35}\b",
    r'(?<="execution_time": )"?[\d.]+"?',
    r'(?<="check_run_interval": )\d+',
    r'(?<="check_interval": )\d+',
    r'(?<="cmd_id": ")[0-9a-f]{32}(?=")',
    # audit markers of values that are stored encrypted with a random IV
    r'(?<="nvd_api_key": "hmac:)[0-9a-f]+',
    r'(?<="dell_api_client_id": "hmac:)[0-9a-f]+',
    r'(?<="dell_api_client_secret": "hmac:)[0-9a-f]+',
]


def reply_for(data):
    # the canned answers of the stand-in agents of the inventory
    f = data.get("func")
    p = data.get("payload") or {}
    if f == "ping":
        return "pong"
    if f == "procs":
        return [
            {
                "name": "svchost.exe",
                "pid": 100,
                "membytes": 1000,
                "username": "SYSTEM",
                "id": 0,
                "cpu_percent": "0.0",
            }
        ]
    if f == "eventlog":
        return [
            {
                "source": "parity",
                "eventType": "INFO",
                "eventID": 1,
                "message": "hello",
                "time": "2026-10-12 10:00:00",
                "uid": 1,
            }
        ]
    if f == "rawcmd":
        return "fake-output"
    if f == "runscript":
        return "fake-script-out\nlast-line"
    if f == "runscriptfull":
        return {
            "stdout": "fake-script-out",
            "stderr": "",
            "retcode": 0,
            "execution_time": 0.1,
        }
    if f == "registry_browse":
        return {
            "path": p.get("path"),
            "subkeys": ["SOFTWARE"],
            "values": [{"name": "A", "type": "REG_SZ", "data": "x"}],
            "has_more": False,
        }
    if f in (
        "registry_create_key",
        "registry_delete_key",
        "registry_rename_key",
        "registry_delete_value",
        "registry_rename_value",
    ):
        return {"status": "success", "new_name": p.get("new_name")}
    if f in ("registry_create_value", "registry_modify_value"):
        return {
            "status": "success",
            "name": p.get("name"),
            "type": p.get("type"),
            "data": p.get("data"),
        }
    return "ok"


def _unpack(payload):
    try:
        return msgpack.loads(payload)
    except Exception:
        return {"undecodable": True}


class _Msg:
    def __init__(self, data):
        self.data = data


class _Sub:
    async def unsubscribe(self, *a, **kw):
        return None


class FakeNats:
    """What the server sees of NATS: connects, publishes, and answers requests only
    for the agents of the item's nats_agents."""

    def __init__(self):
        self.log = []
        self.agents = set()
        self.ids = {}

    async def connect(self, *a, **kw):
        return _Client(self)

    def answers(self, subject):
        return self.ids.get(subject) in self.agents


class _Client:
    def __init__(self, fake):
        self.fake = fake
        self.is_closed = False

    async def request(self, subject, payload=b"", timeout=None, **kw):
        from nats.errors import NoRespondersError

        data = _unpack(payload)
        self.fake.log.append({"request": subject, "data": data})
        if not self.fake.answers(subject):
            raise NoRespondersError
        return _Msg(msgpack.dumps(reply_for(data if isinstance(data, dict) else {})))

    async def publish(self, subject, payload=b"", **kw):
        self.fake.log.append({"publish": subject, "data": _unpack(payload)})

    async def subscribe(self, subject, *a, **kw):
        return _Sub()

    async def flush(self, *a, **kw):
        return None

    async def drain(self, *a, **kw):
        self.is_closed = True

    async def close(self, *a, **kw):
        self.is_closed = True


# --- names and sockets ---------------------------------------------------------

_real_getaddrinfo = socket.getaddrinfo
_real_connect = socket.socket.connect
_real_connect_ex = socket.socket.connect_ex


def own_ip():
    import psutil

    for entries in psutil.net_if_addrs().values():
        for e in entries:
            if e.family == socket.AF_INET and not e.address.startswith("127."):
                return e.address
    return "127.0.0.1"


def _literal(host):
    try:
        ipaddress.ip_address(str(host).split("%")[0])
        return True
    except ValueError:
        return False


def _getaddrinfo(host, *a, **kw):
    if isinstance(host, bytes):
        host = host.decode()
    if host is None or _literal(host):
        return _real_getaddrinfo(host, *a, **kw)
    ip = (CASE.hosts if CASE else {}).get(str(host).lower().rstrip("."))
    if ip is None:
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
    return _real_getaddrinfo(ip, *a, **kw)


def _gethostbyname(host):
    return _getaddrinfo(host, None, socket.AF_INET)[0][4][0]


def _local(sock, address):
    if sock.family not in (socket.AF_INET, socket.AF_INET6):
        return True
    try:
        return ipaddress.ip_address(str(address[0]).split("%")[0]).is_loopback
    except ValueError:
        return False


def _target(sock, address):
    from ulrmm.helpers import get_nats_ports

    if CASE and tuple(address[:2]) == (LAN_IP, 8080):
        return ("127.0.0.1", CASE.lan.port)
    if not _local(sock, address):
        return None
    # NATS is the stand-in: a real one next to the test (shared loopback) stays shut
    if sock.family != socket.AF_UNIX and address[1] in get_nats_ports():
        return None
    return address


def _connect(sock, address):
    target = _target(sock, address)
    if target is None:
        raise ConnectionRefusedError(111, "Connection refused")
    return _real_connect(sock, target)


def _connect_ex(sock, address):
    target = _target(sock, address)
    if target is None:
        return 111
    return _real_connect_ex(sock, target)


# --- small local servers -------------------------------------------------------


class _Server:
    def __init__(self, handler, **attrs):
        class H(handler):
            pass

        for k, v in attrs.items():
            setattr(H, k, v)
        self.srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), H)
        self.srv.daemon_threads = True
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


class _Smtp(socketserver.StreamRequestHandler):
    # the mail sink of the inventory: no TLS, no AUTH, logs envelope and message
    log = ""

    def note(self, text):
        with open(self.log, "a") as fh:
            fh.write(text + "\n")

    def handle(self):
        def out(line):
            self.wfile.write((line + "\r\n").encode())

        out("220 bench ESMTP")
        data_mode, buf = False, []
        for raw in self.rfile:
            text = raw.decode(errors="replace").rstrip("\r\n")
            if data_mode:
                if text == ".":
                    data_mode = False
                    keep = [
                        x
                        for x in buf
                        if not x.lower().startswith(("date:", "message-id:"))
                    ]
                    self.note("\n".join(keep) + "\n--END--")
                    buf = []
                    out("250 queued")
                else:
                    buf.append(text)
                continue
            cmd = text.upper()
            if cmd.startswith(("EHLO", "HELO")):
                out("250 bench")
            elif cmd.startswith("MAIL FROM"):
                self.note("FROM " + text.split(":", 1)[1].strip())
                out("250 ok")
            elif cmd.startswith("RCPT TO"):
                self.note("TO " + text.split(":", 1)[1].strip())
                out("250 ok")
            elif cmd == "DATA":
                data_mode = True
                out("354 go")
            elif cmd == "QUIT":
                out("221 bye")
                break
            elif cmd.startswith("STARTTLS"):
                out("502 not supported")
            else:
                out("250 ok")


class _Files(http.server.SimpleHTTPRequestHandler):
    root = ""

    def __init__(self, *a, **kw):
        super().__init__(*a, directory=self.root, **kw)

    def log_message(self, *a):
        pass


class FakeMesh:
    """MeshCentral control socket: answers meshes/nodes/users, logs every frame to
    `log` and reads its scenario from `state` (both JSON files)."""

    def __init__(self, log, state):
        self.log, self.state = log, state
        self.loop = asyncio.new_event_loop()
        ready = threading.Event()
        threading.Thread(target=self._run, args=(ready,), daemon=True).start()
        ready.wait(10)

    def _run(self, ready):
        import websockets

        asyncio.set_event_loop(self.loop)

        async def start():
            self.server = await websockets.serve(
                self.handler, "127.0.0.1", 0, max_size=2**24
            )
            self.port = self.server.sockets[0].getsockname()[1]
            ready.set()

        self.loop.run_until_complete(start())
        self.loop.run_forever()

    async def handler(self, ws, *args):
        async for raw in ws:
            msg = json.loads(raw)
            with open(self.log, "a") as fh:
                fh.write(json.dumps(msg, sort_keys=True) + "\n")
            try:
                with open(self.state) as fh:
                    st = json.load(fh)
            except (OSError, ValueError):
                st = {}
            a = msg.get("action")
            if a == "meshes":
                default = [{"_id": "mesh//grp1", "name": "UniversalLocalRMM"}]
                reply = {"action": "meshes", "meshes": st.get("meshes", default)}
            elif a == "nodes":
                if st.get("nodes_error"):
                    reply = {"action": "nodes", "result": "error"}
                else:
                    reply = {"action": "nodes", "nodes": st.get("nodes", {})}
            elif a == "users":
                reply = {"action": "users", "users": st.get("users", [])}
            elif a == "changedevice":
                reply = {
                    "action": "changedevice",
                    "result": st.get("rename_result", "ok"),
                }
            else:
                reply = {"action": a, "result": "ok"}
            reply["responseid"] = msg.get("responseid")
            await ws.send(json.dumps(reply))

    def close(self):
        async def stop():
            self.server.close()
            await self.server.wait_closed()

        asyncio.run_coroutine_threadsafe(stop(), self.loop).result(10)
        self.loop.call_soon_threadsafe(self.loop.stop)


def make_cert(path, days=90):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ulrmm.demo")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(base.NOW - dt.timedelta(days=1))
        .not_valid_after(base.NOW + dt.timedelta(days=days, hours=1))
        .sign(key, hashes.SHA256())
    )
    os.makedirs(path, exist_ok=True)
    good = cert.public_bytes(serialization.Encoding.PEM)
    for name, data in (("cert.good.pem", good), ("cert.pem", good)):
        with open(os.path.join(path, name), "wb") as fh:
            fh.write(data)
    with open(os.path.join(path, "key.pem"), "wb") as fh:
        fh.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )


def _token(value, info):
    # a Fernet token with a fixed time and IV, so runs compare equal
    from remote.utils import _fernet

    iv = hashlib.sha256(info + value.encode()).digest()[:16]
    return (
        _fernet(info)
        ._encrypt_from_parts(value.encode(), int(base.NOW.timestamp()), iv)
        .decode()
    )


def bench_secrets():
    """The bench kept its secrets encrypted under its own key; written again here they
    read back under the test key as they did there."""
    from agents.models import UNINSTALL_CODE_INFO, Agent
    from core.models import DELL_API_INFO, NVD_KEY_INFO, SECRET_FIELD_INFO, CoreSettings

    plain = {
        "smtp_host_password": "Bench-SMTP-pässwörd!1",
        "twilio_auth_token": "bench-twilio-token-0123456789abcdef",
        "mesh_token": "bench0mesh0token0" + "ab" * 40,
        "ai_api_key": "sk-bench-openai-token-XYZ",
    }
    infos = {k: SECRET_FIELD_INFO[k] for k in plain}
    plain.update(nvd_api_key="bench-nvd-key-123", dell_api_client_id="bench-dell-id")
    plain["dell_api_client_secret"] = "bench-dell-secret"
    infos.update(nvd_api_key=NVD_KEY_INFO, **DELL_API_INFO)
    CoreSettings.objects.update(**{k: _token(v, infos[k]) for k, v in plain.items()})
    code = _token("A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6", UNINSTALL_CODE_INFO)
    Agent.objects.exclude(uninstall_code="").update(uninstall_code=code)


# --- helpers for item code -----------------------------------------------------


def psql(query):
    """The query's result as psql -At -F '|' prints it (text output of every column)."""
    lines = []
    try:
        with transaction.atomic():
            connection.ensure_connection()
            cur = connection.connection.cursor()
            cur.execute(query)
            while True:
                if cur.description:
                    res = cur.pgresult
                    for i in range(res.ntuples):
                        cols = [res.get_value(i, j) for j in range(res.nfields)]
                        lines.append(
                            "|".join(
                                "" if v is None else bytes(v).decode() for v in cols
                            )
                        )
                elif cur.statusmessage:
                    lines.append(cur.statusmessage)
                if not cur.nextset():
                    break
    except Exception as e:
        return "SQLERR " + str(e).strip()[:300]
    return "\n".join(lines).strip()


def sql(query):
    print(psql(query))


@contextlib.contextmanager
def stubs(module=None):
    """No sleeping, no mail and no SMS, as the inventory ran its tasks and probes."""

    def refuse(*a, **k):
        raise ConnectionRefusedError("stubbed network")

    import smtplib

    with contextlib.ExitStack() as st:
        st.enter_context(mock.patch("time.sleep", lambda *a, **k: None))
        st.enter_context(mock.patch.object(smtplib, "SMTP", refuse))
        st.enter_context(mock.patch.object(smtplib, "SMTP_SSL", refuse))
        try:
            import twilio.rest

            st.enter_context(mock.patch.object(twilio.rest, "Client", refuse))
        except ImportError:
            pass
        if module is not None and hasattr(module, "sleep"):
            st.enter_context(mock.patch.object(module, "sleep", lambda *a, **k: None))
        yield


def python(code, stub=False, hide_secrets=False):
    """Runs code as `manage.py shell` would; stdout as printed, optionally without the
    PARITY_VAR lines that carry tokens or keys."""
    ns = dict(vars(shell_command))
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            with stubs() if stub else contextlib.nullcontext():
                exec(compile(code, "<item>", "exec"), ns)
    finally:
        out = buf.getvalue()
        for m in re.finditer(r"^PARITY_VAR (\w+) (.*)$", out, re.M):
            CASE.vars[m.group(1)] = m.group(2).strip()
        if hide_secrets:
            out = "".join(
                x
                for x in out.splitlines(True)
                if not re.match(r"PARITY_VAR \w*(token|key)", x)
            )
        sys.stdout.write(out)


def task(path, args=(), kwargs=None):
    """A celery task (or any function) called in-process; prints RESULT like the
    inventory's runner did."""
    import importlib

    mod_name, fn_name = path.rsplit(".", 1)
    mod = importlib.import_module(mod_name)
    fn = getattr(mod, fn_name)
    with contextlib.redirect_stdout(io.StringIO()), stubs(mod):
        try:
            r = fn(*args, **(kwargs or {}))
            line = "RESULT " + repr(r)
        except Exception as e:
            line = "RESULT EXC %s %s" % (type(e).__name__, str(e)[:160])
    print(line)


def manage(argv, env=None, stderr=True, home=None, tail=None, quiet=False):
    """manage.py <argv> as the command line runs it; returns the exit code.
    stderr: True prints its last two lines when the command failed, "merge" prints
    it after stdout (2>&1), False drops it. tail keeps the last lines (| tail -n)."""
    from django.core.management import ManagementUtility

    args = shlex.split(argv) if isinstance(argv, str) else list(argv)
    out, err = io.StringIO(), io.StringIO()
    rc = 0
    env = dict(env or {}, **({"HOME": home} if home else {}))
    with contextlib.ExitStack() as st:
        st.enter_context(mock.patch.object(connections, "close_all", lambda: None))
        if env:
            st.enter_context(mock.patch.dict(os.environ, env))
        st.enter_context(contextlib.redirect_stdout(out))
        st.enter_context(contextlib.redirect_stderr(err))
        try:
            ManagementUtility(["manage.py"] + args).execute()
        except SystemExit as e:
            rc = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
    text = out.getvalue()
    if stderr == "merge":
        text += err.getvalue()
    if tail:
        text = "".join(text.splitlines(True)[-tail:])
    if not quiet:
        sys.stdout.write(text)
    if rc and stderr is True:
        lines = base.MASKS[3][0].sub("", err.getvalue()).strip().splitlines()[-2:]
        print("STDERR " + json.dumps(lines))
    return rc


def uniq_c(values):
    """sort | uniq -c"""
    counts = {}
    for v in values:
        counts[v] = counts.get(v, 0) + 1
    for v in sorted(counts):
        print("%7d %s" % (counts[v], v))


def stepup(token, code):
    import urllib.error
    import urllib.request

    req = urllib.request.Request(
        f"http://localhost:{base.PORT}/accounts/users/console_stepup/",
        data=json.dumps({"code": code}).encode(),
        headers={"Authorization": f"Token {token}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        r = urllib.request.urlopen(req)
        print("stepup", r.status, r.read().decode())
    except urllib.error.HTTPError as e:
        print("stepup FAILED", e.code, e.read().decode())


def http(method, path, token=None, body=None, headers=None):
    """A request from item code, answered in-process; returns (status, text)."""
    import urllib.error
    import urllib.request

    h = dict(headers or {})
    if token:
        h["Authorization"] = f"Token {token}"
    data = None
    if body is not None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        h.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(
        f"http://localhost:{base.PORT}{path}", data=data, headers=h, method=method
    )
    try:
        r = urllib.request.urlopen(req)
        return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def cache_keys(pattern="*"):
    """Keys of the process cache as redis-cli --scan would list them."""
    return sorted(k.decode() for k in cache.iter_keys_pattern(pattern))


def cache_raw(key):
    """The stored (pickled) bytes of a cache entry, b"" when it is missing."""
    with cache._lock:
        return cache._cache.get(cache.make_key(key), b"")


def broker():
    from ulrmm.celery import app

    with app.connection_for_write() as c:
        return c.default_channel.client


def _messages(raw):
    out = []
    for x in raw:
        try:
            m = json.loads(x)
            body = json.loads(base64.b64decode(m["body"]))
            kw = {k: v for k, v in body[1].items() if k != "history_pk"}
            out.append(
                {"task": m["headers"].get("task"), "args": body[0], "kwargs": kw}
            )
        except Exception:
            out.append({"raw": str(x)[:200]})
    return out


# --- websockets ------------------------------------------------------------------


async def _receive(comm, timeout):
    # like receive_output, but a timeout leaves the application running
    if comm.future.done():
        comm.future.result()
    get = asyncio.ensure_future(comm.output_queue.get())
    done, _ = await asyncio.wait(
        {get, comm.future}, timeout=timeout, return_when=asyncio.FIRST_COMPLETED
    )
    if get in done:
        return get.result()
    get.cancel()
    if comm.future in done:
        comm.future.result()
        if not comm.output_queue.empty():
            return comm.output_queue.get_nowait()
        return {"type": "websocket.close", "code": 1000}
    raise asyncio.TimeoutError


async def _probe_sockets(spec):
    from channels.testing import WebsocketCommunicator

    from ulrmm.asgi import application

    out = []
    counts = {}
    for s in spec["sockets"]:
        for st in s["steps"]:
            if "barrier" in st:
                counts[st["barrier"]] = counts.get(st["barrier"], 0) + 1
    barriers = {k: [v, 0, asyncio.Event()] for k, v in counts.items()}

    async def arrive(b):
        bar = barriers[b]
        bar[1] += 1
        if bar[1] >= bar[0]:
            bar[2].set()
        await bar[2].wait()

    async def run(sock):
        name, steps = sock["name"], sock["steps"]

        def emit(**kw):
            out.append(json.dumps({"sock": name, **kw}, sort_keys=True))

        comm = WebsocketCommunicator(application, sock["path"])
        try:
            ok, code = await comm.connect(timeout=10)
        except Exception as e:
            ok, code = None, f"{type(e).__name__}: {e}"
        if not ok:
            # a close before accept was an HTTP 403 handshake answer, an error a 500
            http = 403 if ok is False else 500
            emit(
                connect_error="InvalidStatusCode: server rejected WebSocket "
                f"connection: HTTP {http}",
                **({"close": code} if ok is False else {"error": code}),
            )
            for st in steps:
                if "barrier" in st:
                    await arrive(st["barrier"])
            with contextlib.suppress(Exception):
                await comm.disconnect()
            return
        closed, close_code = False, None

        async def frame(timeout):
            nonlocal closed, close_code
            m = await _receive(comm, timeout)
            if m["type"] == "websocket.close":
                closed, close_code = True, m.get("code", 1000)
                return None
            text = m.get("text")
            try:
                return json.loads(text)
            except (TypeError, ValueError):
                return text if text is not None else m.get("bytes", b"").decode()

        for st in steps:
            if "send" in st:
                if not closed:
                    await comm.send_to(text_data=json.dumps(st["send"]))
            elif "sleep" in st:
                await asyncio.sleep(st["sleep"])
            elif "barrier" in st:
                await arrive(st["barrier"])
            elif "close" in st:
                if not closed:
                    await comm.disconnect()
                    closed, close_code = True, 1000
            elif "recv" in st:
                for _ in range(st["recv"]):
                    if closed:
                        break
                    try:
                        m = await frame(st.get("timeout", 5))
                    except asyncio.TimeoutError:
                        emit(recv_timeout=True)
                        break
                    if not closed:
                        emit(recv=m)
        try:
            while not closed:
                m = await frame(spec.get("drain", 1.0))
                if not closed:
                    emit(late=m)
        except asyncio.TimeoutError:
            pass
        except Exception as e:
            emit(error=type(e).__name__)
        if not closed:
            with contextlib.suppress(Exception):
                await comm.disconnect()
            close_code = 1000
        emit(close_code=close_code)

    await asyncio.gather(*(run(s) for s in spec["sockets"]))
    return out


async def _core_socket(cfg):
    # the single socket runner of the core inventory: open, frames, close codes
    from channels.testing import WebsocketCommunicator

    from ulrmm.asgi import application

    out = {"events": []}
    comm = WebsocketCommunicator(application, cfg["path"])
    try:
        ok, code = await comm.connect(timeout=10)
    except Exception as e:
        out["events"] += ["fail:InvalidStatusCode:500", {"error": type(e).__name__}]
        return out
    if not ok:
        out["events"] += ["fail:InvalidStatusCode:403", {"close": code}]
        return out
    out["events"].append("open")
    closed = []

    async def recv(timeout):
        m = await _receive(comm, timeout)
        if m["type"] == "websocket.close":
            closed.append(m.get("code", 1000))
            raise ConnectionError(m.get("code", 1000))
        return m.get("text")

    for m in cfg.get("send", []):
        await comm.send_to(text_data=json.dumps(m))
    if cfg.get("until"):
        buf = ""
        try:
            while cfg["until"] not in buf:
                r = await recv(cfg.get("timeout", 8))
                buf += json.loads(r).get("data", {}).get("output", "")
            out["events"].append({"until": True})
        except asyncio.TimeoutError:
            out["events"].append({"until": False, "why": "TimeoutError"})
        except ConnectionError:
            out["events"].append({"until": False, "why": "ConnectionClosedOK"})
    for _ in range(0 if cfg.get("until") else cfg.get("recv", 1)):
        try:
            out["events"].append(json.loads(await recv(cfg.get("timeout", 8))))
        except asyncio.TimeoutError:
            out["events"].append("timeout")
            break
        except ConnectionError as e:
            out["events"].append("closed:%s:%s" % (_closed_name(e.args[0]), e.args[0]))
            break
    # after an until loop the shell may still be printing: nothing more to compare
    if not closed and not cfg.get("until"):
        try:
            await recv(cfg.get("close_wait", 0.5))
        except asyncio.TimeoutError:
            out["events"].append("after:TimeoutError:")
        except ConnectionError as e:
            out["events"].append("after:%s:%s" % (_closed_name(e.args[0]), e.args[0]))
    with contextlib.suppress(Exception):
        await comm.disconnect()
    return out


def _closed_name(code):
    return "ConnectionClosedOK" if code in (1000, 1001) else "ConnectionClosedError"


def websocket(spec):
    from asgiref.sync import async_to_sync

    layers = {"default": {"BACKEND": "channels.layers.InMemoryChannelLayer"}}
    with override_settings(CHANNEL_LAYERS=layers), mock.patch(
        "channels.db.close_old_connections", lambda: None
    ):
        if "sockets" in spec:
            return "\n".join(async_to_sync(_probe_sockets)(spec))
        return json.dumps(async_to_sync(_core_socket)(spec))


# --- effects -------------------------------------------------------------------

# columns the inventory left out when it compared rows before and after
VOLATILE = {
    "last_seen",
    "modified_time",
    "created_time",
    "time",
    "entry_time",
    "keep_awake_until",
}


def _rows(table):
    with connection.cursor() as c:
        c.execute(f"select coalesce(json_agg(to_jsonb(x)), '[]') from {table} x")
        return {r["id"]: r for r in c.fetchone()[0]}


def _count(table):
    with connection.cursor() as c:
        c.execute(f"select count(*) from {table}")
        return c.fetchone()[0]


def snapshot(specs):
    snap = {}
    for spec in specs:
        if spec == "celery":
            snap[spec] = broker().llen("celery")
        elif spec.startswith("count:"):
            snap[spec] = _count(spec[6:])
        else:
            snap[spec] = _rows(spec)
    return snap


def changes(specs, before):
    out = {}
    for spec in specs:
        b = before[spec]
        if spec == "celery":
            n = broker().llen("celery") - b
            if n > 0:
                out[spec] = list(
                    reversed(_messages(broker().lrange("celery", 0, n - 1)))
                )
        elif spec.startswith("count:"):
            d = _count(spec[6:]) - b
            if d:
                out[spec] = d
        else:
            a, ch = _rows(spec), {}
            for pk in sorted(set(a) | set(b)):
                if pk not in a:
                    ch[f"-{pk}"] = None
                elif pk not in b:
                    ch[f"+{pk}"] = a[pk]
                else:
                    diff = {
                        k: a[pk].get(k)
                        for k in set(a[pk]) | set(b[pk])
                        if k not in VOLATILE and a[pk].get(k) != b[pk].get(k)
                    }
                    if diff:
                        ch[f"~{pk}"] = diff
            if ch:
                out[spec] = ch
    return out


def _by_id(o):
    if isinstance(o, dict):
        return {k: _by_id(v) for k, v in o.items()}
    if isinstance(o, list):
        items = [_by_id(v) for v in o]
        if items and all(isinstance(v, dict) and "id" in v for v in items):
            items.sort(key=lambda v: json.dumps(v, sort_keys=True))
        return items
    return o


def _dump(o):
    return json.dumps(o, indent=1, sort_keys=True, ensure_ascii=False, default=str)


class R3Case(base.GoldenCase):
    hosts = {"localhost": "127.0.0.1"}
    # certificate files and a systemctl stub, as the core bench had them
    servers = False

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.fake_nats = FakeNats()
        cls.tmp = tempfile.mkdtemp(prefix="golden-")
        for d in ("home", "www", "lan/usr", "cert"):
            os.makedirs(os.path.join(cls.tmp, d))
        cls.home = os.path.join(cls.tmp, "home")
        # what ran next to the server: MeshCentral, a mail sink, file servers
        cls.mesh = FakeMesh(
            os.path.join(cls.tmp, "fm.jsonl"), os.path.join(cls.tmp, "fm-state.json")
        )
        cls.smtp = _Server(_Smtp, log=os.path.join(cls.tmp, "fs.log"))
        cls.www = _Server(_Files, root=os.path.join(cls.tmp, "www"))
        cls.lan = _Server(_Files, root=os.path.join(cls.tmp, "lan"))
        extra = {"MESH_PORT": cls.mesh.port}
        env = {}
        if cls.servers:
            make_cert(os.path.join(cls.tmp, "cert"))
            bindir = os.path.join(cls.tmp, "bin")
            os.makedirs(bindir)
            with open(os.path.join(bindir, "systemctl"), "w") as fh:
                fh.write("#!/bin/sh\nexit 3\n")
            os.chmod(os.path.join(bindir, "systemctl"), 0o755)
            extra.update(
                CERT_FILE=os.path.join(cls.tmp, "cert", "cert.pem"),
                KEY_FILE=os.path.join(cls.tmp, "cert", "key.pem"),
            )
            env["PATH"] = bindir + ":" + os.environ.get("PATH", "")
        cls.server_env = mock.patch.dict(os.environ, env)
        cls.server_env.start()
        cls.server_settings = override_settings(**extra)
        cls.server_settings.enable()

    @classmethod
    def tearDownClass(cls):
        import shutil

        cls.server_settings.disable()
        cls.server_env.stop()
        for srv in (cls.mesh, cls.smtp, cls.www, cls.lan):
            srv.close()
        shutil.rmtree(cls.tmp, ignore_errors=True)
        super().tearDownClass()

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.vars = {}
        path = base.HERE / "items" / f"{cls.area}.prelude"
        buf = io.StringIO()
        with time_machine.travel(base.NOW, tick=False), contextlib.redirect_stdout(buf):
            bench_secrets()
            if path.exists():
                code = compile(path.read_text(), str(path), "exec")
                exec(code, dict(vars(shell_command)))
        for line in buf.getvalue().splitlines():
            m = re.match(r"PARITY_VAR (\w+) (.*)", line)
            if m:
                cls.vars[m.group(1)] = m.group(2).strip()

    def setUp(self):
        global CASE
        super().setUp()
        CASE = self
        self.addCleanup(globals().__setitem__, "CASE", None)
        self.vars = dict(type(self).vars)
        self.hosts = dict(type(self).hosts, **{"bench-self.test": own_ip()})
        self.fake_nats.log.clear()
        for target, new in (
            ("nats.connect", self.fake_nats.connect),
            ("socket.getaddrinfo", _getaddrinfo),
            ("socket.gethostbyname", _gethostbyname),
        ):
            p = mock.patch(target, new)
            p.start()
            self.addCleanup(p.stop)
        for name, new in (("connect", _connect), ("connect_ex", _connect_ex)):
            p = mock.patch.object(socket.socket, name, new)
            p.start()
            self.addCleanup(p.stop)
        for name in ("fm.jsonl", "fm-state.json", "fs.log"):
            with contextlib.suppress(FileNotFoundError):
                os.remove(os.path.join(self.tmp, name))

    def sub(self, o):
        if not isinstance(o, str):
            return super().sub(o)
        m = re.fullmatch(r"\{\{VAR:(\w+)\}\}", o)
        if m and str(self.vars.get(m.group(1), "")).isdigit():
            return int(self.vars[m.group(1)])
        o = re.sub(
            r"\{\{VAR:(\w+)\}\}", lambda m: str(self.vars.get(m.group(1), "")), o
        )
        for k, v in (
            ("{{SMTP_PORT}}", self.smtp.port),
            ("{{MESH_PORT}}", self.mesh.port),
            ("{{HTTP_PORT}}", self.www.port),
            ("{{HOME}}", self.home),
            ("{{TMP}}", self.tmp),
            ("{{OWN_IP}}", self.hosts["bench-self.test"]),
        ):
            o = o.replace(k, str(v))
        return super().sub(o)

    def shell(self, code):
        status, out, err = super().shell(code)
        for line in out.splitlines():
            m = re.match(r"PARITY_VAR (\w+) (.*)", line)
            if m:
                self.vars[m.group(1)] = m.group(2).strip()
        return status, out, err

    def from_get(self, spec, token):
        # a body made from what a GET answers, as the web form sends it back
        headers = {
            **self.auth_headers(spec.get("$as") or token),
            **self.sub(spec.get("$headers") or {}),
        }
        status, _, raw = self.http("GET", self.sub(spec["$from_get"]), headers, None)
        try:
            body = json.loads(raw)
        except ValueError:
            return {"$from_get_failed": status}
        if not isinstance(body, dict):
            return {"$from_get_failed": status}
        for k in spec.get("$drop", []):
            body.pop(k, None)
        body.update(self.sub(spec.get("$set", {})))
        return body

    def http(self, method, path, headers, body):
        # behind uvicorn the client address came from X-Forwarded-For (proxy headers)
        xff = {k.lower(): v for k, v in headers.items()}.get("x-forwarded-for")
        if not xff:
            return super().http(method, path, headers, body)
        real = self.client.generic

        def generic(*a, **kw):
            return real(*a, REMOTE_ADDR=xff.split(",")[-1].strip(), **kw)

        with mock.patch.object(self.client, "generic", generic):
            return super().http(method, path, headers, body)

    def follow(self, method, headers, status, rheaders, raw):
        # redirects as urllib follows them: GET/HEAD always, POST after 301-303 as GET
        for _ in range(10):
            if status not in (301, 302, 303, 307, 308) or "location" not in rheaders:
                break
            if not (
                method in ("GET", "HEAD")
                or (status in (301, 302, 303) and method == "POST")
            ):
                break
            method = "GET" if method == "POST" else method
            headers = {k: v for k, v in headers.items() if k.lower() != "content-type"}
            path = base.urlsplit(rheaders["location"])
            status, rheaders, raw = self.http(
                method,
                path.path + ("?" + path.query if path.query else ""),
                headers,
                None,
            )
        return status, rheaders, raw

    def masks_for(self, it):
        masks = MASKS + list((it.get("compare") or {}).get("mask") or [])
        own = self.hosts["bench-self.test"]
        if own != "127.0.0.1":
            masks.append(re.escape(own))
        return masks + [
            re.escape(self.tmp),
            re.escape(connection.settings_dict["NAME"]),
            rf"(?<=127\.0\.0\.1:)({self.www.port}|{self.mesh.port})\b",
        ]

    def execute(self, it):
        if it.get("settings"):
            with override_settings(**self.sub(it["settings"])):
                return self.run_item(it)
        return self.run_item(it)

    def run_item(self, it):
        if it.get("setup"):
            self.shell(self.sub(it["setup"]))
        c = it.get("compare") or {}
        effects = c.get("effects") or []
        before = snapshot(effects) if effects else None
        self.fake_nats.log.clear()
        self.fake_nats.agents = set(it.get("nats_agents") or [])
        if self.fake_nats.agents:
            from agents.models import Agent

            self.fake_nats.ids = dict(Agent.objects.values_list("agent_id", "pk"))
        method = it.get("method", "GET").upper()
        statuses = []
        if method == "SHELL":
            status, text, _ = self.shell(self.sub(it["shell"]))
            headers = {}
        elif method == "WS":
            with self.guard():
                text = websocket(self.sub(it["ws"]))
            status, headers = 0, {}
        else:
            headers = {
                **self.auth_headers(it.get("token")),
                **self.sub(it.get("headers") or {}),
            }
            body = it.get("body")
            if body is not None:
                if isinstance(body, dict) and "$from_get" in body:
                    body = self.from_get(body, it.get("token"))
                else:
                    body = self.sub(body)
                if isinstance(body, str) and it.get("raw_body"):
                    body = body.encode()
                else:
                    body = json.dumps(body).encode()
                    headers.setdefault("Content-Type", "application/json")
            path = self.sub(it["path"])
            for i in range(it.get("repeat") or 1):
                h = dict(headers)
                for k, v in (it.get("vary_headers") or {}).items():
                    h[k] = v.replace("{i}", str(i))
                status, rheaders, raw = self.http(method, path, h, body)
                if it.get("follow"):
                    status, rheaders, raw = self.follow(
                        method, h, status, rheaders, raw
                    )
                statuses.append(status)
            headers = rheaders
            text = raw.decode("utf-8", "replace")
        masks = self.masks_for(it)
        kind = c.get("body", "json")
        if kind == "ignore":
            text = ""
        elif kind == "json":
            try:
                parsed = json.loads(text)
                if it.get("unordered") == "id":
                    parsed = _by_id(parsed)
                elif it.get("unordered"):
                    parsed = base._sorted(parsed)
                text = json.dumps(parsed, indent=1, sort_keys=True, ensure_ascii=False)
            except ValueError:
                text = "NOT JSON: " + text
        rec = {
            "status": status if c.get("status", True) else None,
            "body_masked": base.apply_masks(text, masks),
        }
        if len(statuses) > 1:
            rec["statuses"] = statuses
        if c.get("headers"):
            rec["headers"] = {h: headers.get(h) for h in c["headers"]}
            if rec["headers"].get("allow"):
                # function views keep their methods in a set
                allow = sorted(m.strip() for m in rec["headers"]["allow"].split(","))
                rec["headers"]["allow"] = ", ".join(allow)
        if effects:
            with self.guard():
                rec["effects_masked"] = base.apply_masks(
                    _dump(changes(effects, before)), masks
                )
        for name, q in (it.get("capture") or {}).items():
            with self.guard():
                v = psql(self.sub(q))
            self.vars[name] = (
                v.splitlines()[0] if v and not v.startswith("SQLERR") else ""
            )
        if self.rolled_back:
            rec["rolled_back"], self.rolled_back = self.rolled_back, []
        if c.get("db"):
            snap = self.db_snapshot(c["db"])
            rec["db_masked"] = {
                spec: base.apply_masks(
                    json.dumps(
                        base._sorted(snap[spec]) if it.get("unordered") else snap[spec],
                        indent=1,
                        sort_keys=True,
                        ensure_ascii=False,
                    ),
                    masks,
                )
                for spec in c["db"]
            }
        if c.get("sql"):
            with self.guard():
                # rows as a sorted list: ties in ORDER BY come back in table order
                rows = [
                    "\n".join(sorted(psql(self.sub(q)).splitlines())) for q in c["sql"]
                ]
            rec["sql_masked"] = [base.apply_masks(r, masks) for r in rows]
        if it.get("post"):
            _, out, _ = self.shell(self.sub(it["post"]))
            rec["post_masked"] = base.apply_masks(out, masks)
        if self.fake_nats.log:
            # concurrent sends (asyncio.gather) arrive in any order
            log = sorted(
                self.fake_nats.log, key=lambda m: json.dumps(m, sort_keys=True)
            )
            rec["nats_masked"] = base.apply_masks(_dump(log), masks)
        if it.get("cleanup"):
            self.shell(self.sub(it["cleanup"]))
        return rec

    def check(self, it, chain):
        for before in chain:
            self.execute(before)
        rec = self.execute(it)
        if base.RECORD:
            type(self).recorded[it["id"]] = rec
            return
        want = self.golden.get(it["id"])
        if want is None:
            self.fail(f"{it['id']}: no golden answer, record with GOLDEN_RECORD=1")
        if rec != want:
            diff = base.difflib.unified_diff(
                render(want), render(rec), "golden", "now", lineterm="", n=2
            )
            self.fail(f"{it['id']}: {it.get('desc', '')}\n" + "\n".join(diff))


def render(rec):
    out = base._render(rec)
    for key in (
        "statuses",
        "effects_masked",
        "sql_masked",
        "post_masked",
        "nats_masked",
    ):
        if key in rec:
            v = rec[key]
            out += [f"#{key}"] + (v if isinstance(v, str) else _dump(v)).splitlines()
    if "rolled_back" in rec:
        out.append("#rolled_back " + json.dumps(rec["rolled_back"]))
    return out


def chain(items, n, index):
    """The items that run before item n: what it names in "after" (and what those
    name), otherwise what base.chain_for finds."""
    seen, order = set(), []

    def need(i):
        for dep in items[i].get("after") or []:
            j = index[dep]
            if j not in seen:
                seen.add(j)
                need(j)
                order.append(j)

    need(n)
    if order:
        return [items[j] for j in sorted(order)]
    return base.chain_for(items, n)


def add_items(case):
    items = json.loads((base.HERE / "items" / f"{case.area}.json").read_text())
    index = {it["id"]: n for n, it in enumerate(items)}
    for n, it in enumerate(items):

        def test(self, it=it, pre=chain(items, n, index)):
            self.check(it, pre)

        test.__doc__ = it.get("desc")
        name = "test_" + re.sub(r"\W", "_", it["id"])
        test.__name__ = name
        if it.get("skip"):
            test = unittest.skip(it["skip"])(test)
        setattr(case, name, test)
    return case
