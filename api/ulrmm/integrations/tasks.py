# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""UniFi and OPNsense sync: where each MAC sits in the network.

Read-only GET requests (and the UniFi login). Nothing is changed on either
side. Results go to NetworkClient, Agent.network_info and the discovered
devices."""

import datetime as dt
from contextlib import suppress
from ipaddress import IPv4Address, IPv4Interface
from urllib.parse import quote

import requests
from cryptography.fernet import InvalidToken
from django.utils import timezone as djangotime

from agents.models import Agent
from agents.utils import MAC_RE, reported_macs
from discovery.models import DiscoveredDevice
from logs.models import DebugLog
from netmon.probe import clean
from remote.utils import decrypt_secret
from ulrmm.celery import app
from ulrmm.utils import redis_lock

from .models import (
    OPNSENSE_INFO,
    UNIFI_INFO,
    NetworkClient,
    OpnsenseFirewall,
    UniFiController,
)

SYNC_LOCK = "integrations-sync-lock"
TIMEOUT = 20
# clients not seen for this long are dropped
KEEP = dt.timedelta(days=30)
CLIENT_FIELDS = (
    "ip",
    "hostname",
    "vlan_id",
    "vlan_name",
    "switch",
    "port",
    "ap",
    "ssid",
    "source",
    "last_seen",
)


class SyncError(Exception):
    pass


def _call(session, method: str, base: str, path: str, **kwargs):
    # redirects are not followed, so every request stays on the https base
    r = session.request(
        method, base + path, timeout=TIMEOUT, allow_redirects=False, **kwargs
    )
    if r.is_redirect or 300 <= r.status_code < 400:
        raise SyncError(f"{path} answered with a redirect")
    if r.status_code in (401, 403):
        raise SyncError(f"{path}: the login or key was refused ({r.status_code})")
    if r.status_code >= 400:
        raise SyncError(f"{path} answered {r.status_code}")
    try:
        return r.json()
    except ValueError:
        raise SyncError(f"{path} did not answer with JSON")


def _list(value, key: str, path: str) -> list:
    if isinstance(value, dict):
        value = value.get(key)
    if not isinstance(value, list):
        raise SyncError(f"{path} gave an unexpected answer")
    return [v for v in value if isinstance(v, dict)]


def _mac(value) -> str:
    if not isinstance(value, str) or not MAC_RE.fullmatch(value):
        return ""
    return value.lower().replace("-", ":")


def _ip(value):
    with suppress(ValueError, TypeError):
        return str(IPv4Address(value))
    return None


def _int(value):
    with suppress(ValueError, TypeError):
        return int(value)
    return None


def _subnet(value) -> str:
    with suppress(ValueError, TypeError):
        return str(IPv4Interface(value).network)
    return ""


def _seen(epoch, now):
    with suppress(ValueError, TypeError, OverflowError, OSError):
        return dt.datetime.fromtimestamp(int(epoch), dt.timezone.utc)
    return now


def _session(obj) -> tuple[requests.Session, str]:
    s = requests.Session()
    s.verify = obj.verify_tls
    return s, obj.url.rstrip("/")


def unifi_fetch(c: UniFiController, now) -> tuple[dict, list]:
    """({mac: client fields}, vlans) from a UniFi OS console."""
    s, base = _session(c)
    if c.api_key:
        s.headers["X-API-KEY"] = decrypt_secret(c.api_key, UNIFI_INFO)
    else:
        password = decrypt_secret(c.password, UNIFI_INFO) if c.password else ""
        _call(
            s,
            "POST",
            base,
            "/api/auth/login",
            json={"username": c.username, "password": password},
        )
    api = f"/proxy/network/api/s/{quote(c.site, safe='')}"
    get = {}
    for name in ("rest/networkconf", "stat/device", "stat/sta"):
        path = f"{api}/{name}"
        get[name] = _list(_call(s, "GET", base, path), "data", path)

    networks = {}
    for n in get["rest/networkconf"]:
        if n.get("purpose") == "wan":
            continue
        vid = _int(n.get("vlan")) if n.get("vlan_enabled", True) else None
        networks[n.get("_id")] = {
            # the untagged network is VLAN 1
            "vlan_id": vid or 1,
            "name": clean(n.get("name") or "", 64),
            "subnet": _subnet(n.get("ip_subnet")),
        }
    names = {
        _mac(d.get("mac")): clean(d.get("name") or d.get("model") or d["mac"], 128)
        for d in get["stat/device"]
        if _mac(d.get("mac"))
    }

    clients = {}
    for sta in get["stat/sta"]:
        mac = _mac(sta.get("mac"))
        if not mac:
            continue
        net = networks.get(sta.get("network_id")) or {}
        wired = sta.get("is_wired", not sta.get("ap_mac"))
        row = {
            "ip": _ip(sta.get("ip")),
            "hostname": clean(sta.get("name") or sta.get("hostname") or "", 255),
            "vlan_id": net.get("vlan_id") or _int(sta.get("vlan")),
            "vlan_name": net.get("name") or clean(sta.get("network") or "", 64),
            "last_seen": _seen(sta.get("last_seen"), now),
        }
        if wired:
            row["switch"] = names.get(_mac(sta.get("sw_mac")), "")
            row["port"] = clean(sta.get("sw_port") or "", 32)
        else:
            row["ap"] = names.get(_mac(sta.get("ap_mac")), "")
            row["ssid"] = clean(sta.get("essid") or "", 64)
        clients[mac] = row
    return clients, sorted(networks.values(), key=lambda v: (v["vlan_id"], v["name"]))


def opnsense_fetch(f: OpnsenseFirewall, now) -> tuple[dict, list]:
    """({mac: client fields}, vlans) from the ARP table, the VLANs and the
    DHCPv4 leases. Leases and interface addresses are optional."""
    s, base = _session(f)
    s.auth = (
        decrypt_secret(f.api_key, OPNSENSE_INFO),
        decrypt_secret(f.api_secret, OPNSENSE_INFO),
    )
    path = "/api/interfaces/vlan_settings/searchItem"
    vlan_rows = _list(_call(s, "GET", base, path), "rows", path)
    path = "/api/diagnostics/interface/getArp"
    arp = _list(_call(s, "GET", base, path), "rows", path)
    leases, config = [], {}
    with suppress(SyncError, requests.RequestException):
        path = "/api/dhcpv4/leases/searchLease"
        leases = _list(_call(s, "GET", base, path), "rows", path)
    with suppress(SyncError, requests.RequestException):
        config = _call(s, "GET", base, "/api/diagnostics/interface/getInterfaceConfig")
    config = config if isinstance(config, dict) else {}

    by_dev, vlans = {}, []
    for v in vlan_rows:
        dev, tag = str(v.get("vlanif") or ""), _int(v.get("tag"))
        if not dev or tag is None:
            continue
        subnet, cfg = "", config.get(dev)
        ipv4 = cfg.get("ipv4") if isinstance(cfg, dict) else None
        for addr in ipv4 if isinstance(ipv4, list) else []:
            if isinstance(addr, dict) and (
                subnet := _subnet(f"{addr.get('ipaddr')}/{addr.get('subnetbits')}")
            ):
                break
        by_dev[dev] = {
            "vlan_id": tag,
            "name": clean(v.get("descr") or dev, 64),
            "subnet": subnet,
        }
        vlans.append(by_dev[dev])

    hostnames = {
        _mac(lease.get("hwaddr")): clean(lease.get("hostname") or "", 255)
        for lease in leases
        if _mac(lease.get("hwaddr"))
    }
    clients = {}
    for entry in arp:
        mac = _mac(entry.get("mac"))
        if not mac or entry.get("expired") is True:
            continue
        net = by_dev.get(entry.get("intf")) or {}
        clients[mac] = {
            "ip": _ip(entry.get("ip")),
            "hostname": hostnames.get(mac) or clean(entry.get("hostname") or "", 255),
            "vlan_id": net.get("vlan_id"),
            "vlan_name": net.get("name")
            or clean(entry.get("intf_description") or "", 64),
            "last_seen": now,
        }
    return clients, sorted(vlans, key=lambda v: (v["vlan_id"], v["name"]))


def store(fetched: dict, now) -> None:
    """fetched: {source: {mac: fields}}. UniFi wins where both know a field."""
    merged = {}
    for source in ("opnsense", "unifi"):
        for mac, row in fetched.get(source, {}).items():
            cur = merged.setdefault(mac, {"source": []})
            cur.update({k: v for k, v in row.items() if v not in (None, "")})
            cur["source"].append(source)
    rows = []
    for mac, row in merged.items():
        fields = {k: v for k, v in row.items() if k in CLIENT_FIELDS}
        fields["source"] = ",".join(row["source"])
        fields.setdefault("last_seen", now)
        rows.append(NetworkClient(mac=mac, **fields))
    NetworkClient.objects.bulk_create(
        rows,
        batch_size=500,
        update_conflicts=True,
        unique_fields=["mac"],
        update_fields=list(CLIENT_FIELDS),
    )
    NetworkClient.objects.filter(last_seen__lt=now - KEEP).delete()


def network_info(c: NetworkClient) -> dict:
    return {
        "mac": c.mac,
        "ip": c.ip,
        "vlan_id": c.vlan_id,
        "vlan_name": c.vlan_name,
        "switch": c.switch,
        "port": c.port,
        "ap": c.ap,
        "ssid": c.ssid,
        "source": c.source,
        "last_seen": c.last_seen.isoformat(),
    }


def link() -> None:
    clients = {c.mac: c for c in NetworkClient.objects.all()}
    by_ip = {c.ip: c for c in clients.values() if c.ip}

    # the nic seen last when an agent has more than one
    agents = Agent.objects.values_list("pk", "wmi_detail__nics", "network_info")
    for pk, nics, old in agents.iterator():
        macs = {m.replace("-", ":") for m in reported_macs(nics)}
        seen = [clients[m] for m in macs if m in clients]
        best = max(seen, key=lambda c: c.last_seen, default=None)
        info = network_info(best) if best else {}
        if info != (old or {}):
            Agent.objects.filter(pk=pk).update(network_info=info)

    changed = []
    fields = ("vlan_id", "vlan_name", "switch", "port", "hostname")
    for d in DiscoveredDevice.objects.all():
        c = clients.get(_mac(d.mac)) or by_ip.get(d.ip)
        before = [getattr(d, f) for f in fields]
        d.vlan_id = c.vlan_id if c else None
        d.vlan_name = c.vlan_name if c else ""
        d.switch = c.switch if c else ""
        d.port = c.port if c else ""
        # only fills a name the scan did not find
        d.hostname = d.hostname or (c.hostname[:255] if c else "")
        if before != [getattr(d, f) for f in fields]:
            changed.append(d)
    DiscoveredDevice.objects.bulk_update(changed, fields, batch_size=500)


def _error(e: Exception) -> str:
    if isinstance(e, InvalidToken):
        return "The stored key or password can no longer be read, enter it again."
    return clean(e, 300) or type(e).__name__


def sync() -> dict:
    """Both integrations that are on. {source: {ok, error | clients, vlans}}."""
    now = djangotime.now()
    results, fetched = {}, {}
    for source, model, fetch in (
        ("opnsense", OpnsenseFirewall, opnsense_fetch),
        ("unifi", UniFiController, unifi_fetch),
    ):
        obj = model.get()
        if not (obj.enabled and obj.url):
            continue
        try:
            clients, vlans = fetch(obj, now)
        except Exception as e:
            error = _error(e)
            # update(), a sync is no settings change for the audit log
            model.objects.filter(pk=obj.pk).update(last_error=error)
            DebugLog.error(message=f"{obj} sync failed: {error}")
            results[source] = {"ok": False, "error": error}
            continue
        model.objects.filter(pk=obj.pk).update(
            last_sync=now, last_error="", vlans=vlans
        )
        fetched[source] = clients
        results[source] = {"ok": True, "clients": len(clients), "vlans": len(vlans)}
    if fetched:
        store(fetched, now)
        link()
    return results


@app.task(bind=True)
def sync_integrations_task(self) -> dict | str:
    with redis_lock(SYNC_LOCK, self.app.oid) as acquired:
        if not acquired:
            return f"{self.app.oid} still running"
        return sync()
