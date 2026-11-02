# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import re

from django.conf import settings

# riddix/agents/write_brand.py bakes the agent's display name with these rules
DEFAULT_PRODUCT = "UniversalLocal RMM"
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


class UnknownAgentIdentity(ValueError):
    """Raised when an agent reports an identity this server does not build."""


def agent_ident() -> dict[str, str]:
    """The placeholder -> value map this server bakes into agent builds and
    install/uninstall scripts.
    """
    prog_dir = settings.AGENT_WIN_PROG_DIR
    reg_key = settings.AGENT_WIN_REG_KEY
    nix_svc = settings.AGENT_NIX_SVC

    heal_base = nix_svc[: -len(".service")] if nix_svc.endswith(".service") else nix_svc

    inno_app_id = settings.AGENT_INNO_APPID
    if inno_app_id.startswith("{{"):
        inno_app_id = inno_app_id.replace("{{", "{", 1)

    return {
        "identSvcName": settings.AGENT_SVC_NAME,
        "identWinExe": settings.AGENT_WIN_EXE,
        "identWinProgDir": prog_dir,
        "identWinProgPath": f"C:\\Program Files\\{prog_dir}",
        "identWinRegKey": reg_key,
        "identWinProgData": f"C:\\ProgramData\\{reg_key}",
        "identNixBin": settings.AGENT_NIX_BIN,
        "identNixDir": settings.AGENT_NIX_DIR,
        "identNixConf": settings.AGENT_NIX_CONF,
        "identNixSvc": nix_svc,
        "identMacPlistLabel": settings.AGENT_MAC_PLIST_LABEL,
        "identArtifact": settings.AGENT_ARTIFACT_NAME,
        "identNixHeal": f"{heal_base}-selfheal",
        "identInnoAppId": inno_app_id,
    }


def brand_agent_name() -> str:
    """BrandAgentName of agents built from the current branding."""
    from core.utils import get_branding

    product = " ".join(_CTRL.sub(" ", str(get_branding().product_name or "")).split())
    if not product or product == DEFAULT_PRODUCT:
        return f"{DEFAULT_PRODUCT} Agent"
    return f"{product} Agent"


def nix_rc_name(ident: dict[str, str]) -> str:
    """FreeBSD rc.d name of the agent service, an rc.conf variable prefix."""
    return ident["identNixSvc"].removesuffix(".service").replace("-", "_")


def agent_ident_for(agent) -> dict[str, str]:
    reported = agent.agent_ident or ""
    mine = agent_ident()
    if reported == mine["identSvcName"]:
        return mine
    raise UnknownAgentIdentity(
        f"{agent.hostname} reports agent identity '{reported}', which this "
        "server does not build. Refusing to send it an agent artifact."
    )


def agent_task_prefix() -> str:
    return settings.AGENT_TASK_PREFIX


def render_agent_script(path, ident: dict[str, str]) -> str:
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    for placeholder, value in ident.items():
        text = text.replace(placeholder, value)
    return text


def agent_artifact(ver: str, plat: str, goarch: str, force_exe: bool = False) -> str:
    name = f"{settings.AGENT_ARTIFACT_NAME}-v{ver}-{plat}-{goarch}"
    if force_exe or plat == "windows":
        name = f"{name}.exe"
    return name


def agent_artifact_for(agent, ver: str, *, force_exe: bool = False) -> str:
    artifact = agent_ident_for(agent)["identArtifact"]
    name = f"{artifact}-v{ver}-{agent.plat}-{agent.goarch}"
    if force_exe or agent.plat == "windows":
        name = f"{name}.exe"
    return name
