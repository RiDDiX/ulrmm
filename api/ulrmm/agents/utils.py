# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import asyncio
import copy
import hashlib
import io
import ipaddress
import re
import socket
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterable, Optional, Union

import psutil
from django.conf import settings
from django.core.cache import cache
from django.db.models import Q
from django.http import FileResponse
from django.shortcuts import get_object_or_404
from rest_framework.response import Response

from core.utils import get_core_settings, get_mesh_ws_url, mesh_installer_sha256
from core.utils import get_mesh_device_id
from ulrmm.agent_ident import (
    agent_artifact,
    agent_artifact_for,
    agent_ident,
    brand_agent_name,
    render_agent_script,
)
from ulrmm.constants import (
    AGENT_DEFER,
    AgentPlat,
    CheckStatus,
    GoArch,
    MeshAgentIdent,
)
from ulrmm.exceptions import NatsDown
from ulrmm.helpers import agent_ver, notify_error
from ulrmm.nats_utils import abulk_nats_command
from ulrmm.util_settings import get_backend_url

if TYPE_CHECKING:
    from django.db.models import QuerySet

    from agents.models import Agent


# who is logged in


def nobody_logged_in(agent) -> bool:
    # windows reports "None", unix agents up to 2.09.10.2026 report ""
    return (agent.logged_in_username or "").strip() in ("", "None")


# shell paths

_SHELL_METACHARS = frozenset("\"'\n\r&|;")
_WIN_DRIVE_PATH = re.compile(r"^[A-Za-z]:\\")


def _clean_path(value) -> str:
    if not isinstance(value, str):
        return ""
    value = value.strip()
    if not value or any(ch in _SHELL_METACHARS for ch in value):
        return ""
    return value


def is_windows_path(value) -> bool:
    """A drive-letter path to an .exe. UNC, device and relative paths fail."""
    path = _clean_path(value)
    return bool(path and _WIN_DRIVE_PATH.match(path) and path.lower().endswith(".exe"))


def is_posix_abs_path(value) -> bool:
    path = _clean_path(value)
    return bool(path) and path.startswith("/")


# agent artifacts

_SHA256_TTL = 60 * 60 * 24


def _self_built_url() -> str:
    return (getattr(settings, "SELF_BUILT_AGENTS_URL", "") or "").strip()


def local_agents_dist_url() -> str:
    backend = get_backend_url(
        settings.ALLOWED_HOSTS[0], settings.ULRMM_PROTO, settings.ULRMM_BACKEND_PORT
    )
    return f"{backend}/agentdist"


def get_agents_dist_url() -> str:
    configured = _self_built_url()
    if configured:
        return configured.rstrip("/")
    return local_agents_dist_url()


def _validate_plat_goarch(plat, goarch) -> None:
    # both come from agent-reported data and end up in URLs, file names and
    # shell commands
    if plat not in AgentPlat.values or goarch not in GoArch.values:
        raise ValueError(f"invalid plat/goarch: {plat}/{goarch}")


def get_install_agent_url(*, goarch: str, plat: str) -> str:
    _validate_plat_goarch(plat, goarch)
    name = agent_artifact(settings.LATEST_AGENT_VER, plat, goarch)
    return f"{get_agents_dist_url()}/{name}"


def get_agent_url(*, agent) -> str:
    _validate_plat_goarch(agent.plat, agent.goarch)
    name = agent_artifact_for(agent, settings.LATEST_AGENT_VER)
    return f"{get_agents_dist_url()}/{name}"


def _dist_dir() -> Path:
    return Path(getattr(settings, "AGENTS_DIST_DIR", "/opt/ulrmm-agents/dist"))


def _dist_sha256(name: str) -> str:
    """sha256 of a file served from the local dist directory, "" if absent."""
    dist = _dist_dir()
    path = dist / name
    try:
        if path.parent.resolve() != dist.resolve():
            return ""
        st = path.stat()
    except (OSError, ValueError):
        return ""
    if not path.is_file():
        return ""

    key = f"agentdist_sha256:{name}:{st.st_size}:{st.st_mtime_ns}"
    cached = cache.get(key)
    if isinstance(cached, str) and cached:
        return cached

    digest = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return ""
    value = digest.hexdigest()
    cache.set(key, value, _SHA256_TTL)
    return value


def get_agent_artifact_sha256(*, agent) -> str:
    _validate_plat_goarch(agent.plat, agent.goarch)
    return _dist_sha256(agent_artifact_for(agent, settings.LATEST_AGENT_VER))


# linux installer

_MESH_LINUX_IDENT = {
    GoArch.AMD64: MeshAgentIdent.LINUX64,
    GoArch.i386: MeshAgentIdent.LINUX32,
    GoArch.ARM64: MeshAgentIdent.LINUX_ARM_64,
    GoArch.ARM32: MeshAgentIdent.LINUX_ARM_HF,
}


def _sh_single_quoted(value) -> str:
    # the template wraps every value in '...'; close, escape, reopen
    return str(value).replace("'", "'\\''")


def install_artifact_sha256(plat: str, goarch: str) -> str:
    """sha256 of the local build an installer downloads, "" when unknown.
    SELF_BUILT_AGENTS_URL serves the same dist directory, so it is hashed too."""
    if plat not in AgentPlat.values or goarch not in GoArch.values:
        return ""
    return _dist_sha256(agent_artifact(settings.LATEST_AGENT_VER, plat, goarch))


def render_linux_install(
    *,
    download_url: str,
    sha256: str,
    mesh_url: str,
    client: str,
    site: str,
    agent_type: str,
    token: str,
    api: str,
    script=None,
    enroll: str = "",
    builds: str = "",
    local_binary: bool = False,
    mesh_sha256: str = "",
) -> str:
    text = render_agent_script(script or settings.LINUX_AGENT_SCRIPT, agent_ident())
    values = {
        "agentDLChange": download_url,
        "agentSha256Change": sha256,
        "meshDLChange": mesh_url,
        "meshSha256Change": mesh_sha256,
        "clientIDChange": client,
        "siteIDChange": site,
        "agentTypeChange": agent_type,
        "tokenChange": token,
        "apiURLChange": api,
        "agentBrandChange": brand_agent_name(),
        "enrollChange": enroll,
        "agentBuildsChange": builds,
        "localBinaryChange": "true" if local_binary else "",
    }
    # one pass, so a value can never be read as another placeholder
    pattern = re.compile("|".join(re.escape(k) for k in values))
    return pattern.sub(lambda m: _sh_single_quoted(values[m.group(0)]), text)


def generate_linux_install(
    client: str,
    site: str,
    agent_type: str,
    arch: str,
    token: str,
    api: str,
    download_url: str,
) -> FileResponse:
    core = get_core_settings()
    ident = _MESH_LINUX_IDENT.get(arch, "not_found")
    mesh_id = asyncio.run(get_mesh_device_id(get_mesh_ws_url(), core.mesh_device_group))
    mesh_url = (
        f"{core.mesh_site}/meshagents?id={mesh_id}&installflags=2&meshinstall={ident}"
    )

    mesh_sha = ""
    if ident != "not_found":
        mesh_sha = mesh_installer_sha256(
            ident=ident,
            plat=AgentPlat.LINUX,
            mesh_device_id=mesh_id,
            mesh_site=core.mesh_site,
        )

    text = render_linux_install(
        download_url=download_url,
        sha256=install_artifact_sha256(AgentPlat.LINUX, arch),
        mesh_url=mesh_url,
        mesh_sha256=mesh_sha,
        client=client,
        site=site,
        agent_type=agent_type,
        token=token,
        api=api,
    )
    return FileResponse(
        io.BytesIO(f"{text}\n".encode()),
        as_attachment=True,
        filename="linux_agent_install.sh",
    )


def generate_freebsd_install(
    client: str,
    site: str,
    agent_type: str,
    arch: str,
    token: str,
    api: str,
    download_url: str,
) -> FileResponse:
    # the agent fetches its mesh agent itself, through /api/v3/meshexe/
    text = render_linux_install(
        download_url=download_url,
        sha256=install_artifact_sha256(AgentPlat.FREEBSD, arch),
        mesh_url="",
        client=client,
        site=site,
        agent_type=agent_type,
        token=token,
        api=api,
        script=settings.FREEBSD_AGENT_SCRIPT,
    )
    return FileResponse(
        io.BytesIO(f"{text}\n".encode()),
        as_attachment=True,
        filename="freebsd_agent_install.sh",
    )


# registry and other agent >= 2.10.0 features


def get_validated_agent(
    agent_id: str, min_version: str = "2.10.0"
) -> "Union[Agent, Response]":
    from agents.models import Agent

    agent = get_object_or_404(Agent.objects.defer(*AGENT_DEFER), agent_id=agent_id)
    if agent_ver(agent.version) < agent_ver(min_version):
        return notify_error(
            f"This feature requires agent version {min_version} or higher."
        )
    return agent


_UNREACHABLE = ("timeout", "natsdown")


def send_nats_command(agent, func: str, payload: dict, timeout: int = 60):
    """Request/reply to the agent. Returns the reply dict or a 400 Response."""
    try:
        reply = asyncio.run(
            agent.nats_cmd({"func": func, "payload": payload}, timeout=timeout)
        )
    except Exception as e:
        return notify_error(f"NATS communication failed: {e}")

    label = func.replace("_", " ").title()
    if isinstance(reply, dict):
        if "error" in reply:
            return notify_error(f"{label} failed: {reply['error']}")
        return reply
    if isinstance(reply, str) and reply not in _UNREACHABLE and reply.strip():
        return notify_error(f"{label} failed: {reply}")
    return notify_error("Unable to contact the agent")


# display probe (headless linux)

DISPLAY_PROBE = (
    "d=absent; "
    "if command -v ss >/dev/null 2>&1; then "
    "ss -xl 2>/dev/null | grep -q '.X11-unix/X' && d=present; "
    "elif ls /tmp/.X11-unix/X* >/dev/null 2>&1; then d=present; fi; "
    "if [ $d = absent ] && systemctl is-active --quiet display-manager 2>/dev/null; "
    "then d=present; fi; "
    "if [ $d = absent ]; then "
    "for s in $(loginctl list-sessions --no-legend 2>/dev/null | awk '{print $1}'); do "
    'case "$(loginctl show-session "$s" -p Type --value 2>/dev/null)" in '
    "x11|wayland) d=present;; esac; done; fi; "
    "echo $d"
)

_DISPLAY_TTL = 60 * 60
_DISPLAY_STATES = ("present", "absent")


def get_agent_display(agent, probe: bool = True) -> str:
    """present | absent | unknown. Only linux can be headless."""
    if agent.plat != AgentPlat.LINUX:
        return "present"

    key = f"agent_display_{agent.agent_id}"
    cached = cache.get(key)
    if cached in _DISPLAY_STATES:
        return cached

    if not probe or not agent.is_online:
        return "unknown"

    data = {
        "func": "rawcmd",
        "timeout": 5,
        "payload": {"command": DISPLAY_PROBE, "shell": "/bin/bash"},
    }
    try:
        reply = asyncio.run(agent.nats_cmd(data, timeout=8))
    except Exception:
        return "unknown"
    if not isinstance(reply, str) or reply.strip() not in _DISPLAY_STATES:
        return "unknown"

    state = reply.strip()
    cache.set(key, state, _DISPLAY_TTL)
    return state


# caching of policy checks/tasks


def strip_relation_caches_for_cache(instances: Iterable, keep=("script",)) -> list:
    """Shallow copies fit for the cache: only the relations in `keep` stay
    loaded and per-agent results are dropped. The originals are untouched."""
    out = []
    for obj in instances:
        clone = copy.copy(obj)
        clone._state = copy.copy(obj._state)
        clone._state.fields_cache = {
            name: value
            for name, value in obj._state.fields_cache.items()
            if name in keep
        }
        clone._prefetched_objects_cache = {}
        clone.__dict__.pop("check_result", None)
        clone.__dict__.pop("task_result", None)
        out.append(clone)
    return out


# check summary

_SEVERITY_BUCKET = {"error": "failing", "warning": "warning", "info": "info"}


def calculate_agent_checks(agent) -> dict[str, Any]:
    from alerts.models import RESULT_SEVERITY_CHECKS

    summary: dict[str, Any] = {
        "total": 0,
        "passing": 0,
        "failing": 0,
        "warning": 0,
        "info": 0,
        "pending": 0,
    }
    for check in agent.get_checks_with_policies(exclude_overridden=True):
        summary["total"] += 1
        result = check.check_result
        # a check that never ran has not passed
        if not result or result.status == CheckStatus.PENDING:
            summary["pending"] += 1
            continue
        if result.status == CheckStatus.PASSING:
            summary["passing"] += 1
            continue
        if result.status != CheckStatus.FAILING:
            continue
        if check.check_type in RESULT_SEVERITY_CHECKS:
            severity = result.alert_severity
        else:
            severity = check.alert_severity
        bucket = _SEVERITY_BUCKET.get(severity)
        if bucket:
            summary[bucket] += 1

    summary["has_failing_checks"] = summary["failing"] > 0 or summary["warning"] > 0
    return summary


# wake-on-LAN

MAC_RE = re.compile(r"[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}")
WOL_PORT = 9
WOL_RELAYS = 3


def magic_packet(mac: str) -> bytes:
    if not isinstance(mac, str) or not MAC_RE.fullmatch(mac):
        raise ValueError(f"invalid mac address: {mac!r}")
    raw = bytes.fromhex(re.sub("[:-]", "", mac))
    return b"\xff" * 6 + raw * 16


def send_magic_packet(macs: Iterable[str], broadcast: str) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for mac in macs:
            sock.sendto(magic_packet(mac), (broadcast, WOL_PORT))


def is_ip(value) -> bool:
    try:
        ipaddress.ip_address(value)
    except (TypeError, ValueError):
        return False
    return True


def _nic_list(nics) -> list[dict]:
    if not isinstance(nics, list):
        return []
    return [nic for nic in nics if isinstance(nic, dict)]


def _valid_mac(nic: dict) -> Optional[str]:
    mac = nic.get("mac")
    if isinstance(mac, str) and MAC_RE.fullmatch(mac):
        return mac.lower()
    return None


def reported_nics(nics) -> list[tuple[str, ipaddress.IPv4Network]]:
    """(mac, network) for every usable IPv4 address an agent reported."""
    out = []
    for nic in _nic_list(nics):
        mac = _valid_mac(nic)
        ips = nic.get("ips")
        if not mac or not isinstance(ips, list):
            continue
        for ip in ips:
            if not isinstance(ip, str):
                continue
            try:
                iface = ipaddress.ip_interface(ip)
            except ValueError:
                continue
            if iface.version != 4 or iface.is_link_local:
                continue
            if not 8 <= iface.network.prefixlen <= 30:
                continue
            out.append((mac, iface.network))
    return out


def reported_macs(nics) -> set[str]:
    return {mac for mac in map(_valid_mac, _nic_list(nics)) if mac}


def server_networks() -> set[ipaddress.IPv4Network]:
    nets = set()
    for addrs in psutil.net_if_addrs().values():
        for addr in addrs:
            if addr.family != socket.AF_INET or not addr.netmask:
                continue
            try:
                iface = ipaddress.IPv4Interface(f"{addr.address}/{addr.netmask}")
            except ValueError:
                continue
            if iface.is_loopback or iface.is_link_local:
                continue
            nets.add(iface.network)
    return nets


def _agent_nics(agent) -> Any:
    wmi = agent.wmi_detail if isinstance(agent.wmi_detail, dict) else {}
    return wmi.get("nics")


def wake_agents(agents: "QuerySet[Agent]", user=None) -> dict[int, list[str]]:
    """Send magic packets for every agent that reported its NICs.

    The server broadcasts on target networks it is attached to itself. Online
    agents on the target's network relay the packet: agents of the same site,
    or, for a dashboard user, agents behind the same public IP. Relays never
    leave the user's scope. Returns {agent pk: [who sent it]}.
    """
    from agents.models import Agent

    targets = []
    for agent in agents:
        nics = _agent_nics(agent)
        macs = sorted(reported_macs(nics))
        if macs:
            nets = {net for _, net in reported_nics(nics)}
            targets.append((agent, macs, nets))
    if not targets:
        return {}

    result: dict[int, list[str]] = {}
    own_nets = server_networks()
    for agent, macs, nets in targets:
        sent = []
        for net in sorted(nets & own_nets, key=str):
            try:
                send_magic_packet(macs, str(net.broadcast_address))
            except OSError:
                continue
            sent.append(f"server ({net})")
        result[agent.pk] = sent

    def real_ip(agent) -> Optional[str]:
        return agent.public_ip if is_ip(agent.public_ip) else None

    scope = Q(site_id__in={agent.site_id for agent, _, _ in targets})
    public_ips = {real_ip(agent) for agent, _, _ in targets} - {None}
    if user is not None and public_ips:
        scope |= Q(public_ip__in=public_ips)

    candidates = Agent.objects.filter(scope, wmi_detail__has_key="nics")
    if user is not None:
        candidates = candidates.filter_by_role(user)
    target_pks = {agent.pk for agent, _, _ in targets}
    relays = [
        (relay, {net for _, net in reported_nics(_agent_nics(relay))})
        for relay in candidates.defer("services").order_by("pk")
        if relay.is_online
    ]
    # targets that are online themselves and macs (often asleep) come last
    relays.sort(key=lambda r: (r[0].pk in target_pks, r[0].plat == AgentPlat.DARWIN))

    picked: dict[int, list[str]] = {}
    relay_macs: dict[int, set[str]] = {}
    relay_by_pk = {}
    for agent, macs, nets in targets:
        chosen = []
        for relay, relay_nets in relays:
            if len(chosen) == WOL_RELAYS:
                break
            if relay.pk == agent.pk or not (relay_nets & nets):
                continue
            same_site = relay.site_id == agent.site_id
            same_ip = (
                user is not None
                and real_ip(agent) is not None
                and relay.public_ip == agent.public_ip
            )
            if not (same_site or same_ip):
                continue
            chosen.append(relay.hostname)
            relay_macs.setdefault(relay.pk, set()).update(macs)
            relay_by_pk[relay.pk] = relay
        picked[agent.pk] = chosen

    if relay_macs:
        items = [
            (
                relay_by_pk[pk].agent_id,
                {"func": "wakeonlan", "macs": sorted(macs)},
            )
            for pk, macs in relay_macs.items()
        ]
        try:
            asyncio.run(abulk_nats_command(items=items))
        except NatsDown:
            return result

    for pk, names in picked.items():
        result[pk] = result[pk] + names
    return result
