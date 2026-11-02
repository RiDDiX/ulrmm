# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import random

from django.conf import settings

from agents.utils import _dist_sha256, local_agents_dist_url
from ulrmm.structs import AgentCheckInConfig

# sha256 of the runtime downloads per pinned version and "plat/goarch". A
# version bump in settings needs its digests here, otherwise the agent gets ""
# and installs unchecked.
RUNTIME_SHA256 = {
    "nushell": {
        "0.112.2": {
            "windows/amd64": "db57750ec878365135e7baebee9f5ec74b84c80158ed0168f1ccbe15d6ec251d",
            "windows/arm64": "badc7536bf502b3d46c5abf6dc84d394641f407617e6be99cc8346fe946c5550",
            "linux/amd64": "d9c0ba0938beed6148c8a354c45612c0979d7a787794b8dd13e866ca3b571375",
            "linux/arm64": "ab32bb605cd11a7d9cfd45c3cb19f6141a724e204b20531802bacd9eb659879b",
            "darwin/arm64": "a61806761db7bc2eddfc313d5ec496c92776a37124bc64a3036374bd55e8c881",
        }
    },
    "deno": {
        "v1.46.3": {
            "windows/amd64": "d9428daa1b3763bdf562054d0fc40832658515b7071c7f7e98d61961adc2d61a",
            "linux/amd64": "39bb1d21ad19c16fcb14f9d58fb542c2bccf0cd92c19aee8127ac5112b48bf83",
            "darwin/amd64": "a7a3d9fcced6f959728457e93270c7e3f612c039cd7c58022094d6fa4ef28fe2",
            "darwin/arm64": "e74f8ddd6d8205654905a4e42b5a605ab110722a7898aef68bc35d6e704c2946",
        }
    },
}

# mirrored into the dist directory by riddix/agents/build_agents.sh
CHOCO_SCRIPT = "chocolatey-install.ps1"

_INTERVALS = {
    "checkin_hello": ("CHECKIN_HELLO", (30, 60)),
    "checkin_agentinfo": ("CHECKIN_AGENTINFO", (200, 400)),
    "checkin_winsvc": ("CHECKIN_WINSVC", (2400, 3000)),
    "checkin_pubip": ("CHECKIN_PUBIP", (300, 500)),
    "checkin_disks": ("CHECKIN_DISKS", (1000, 2000)),
    "checkin_sw": ("CHECKIN_SW", (2800, 3500)),
    "checkin_wmi": ("CHECKIN_WMI", (3000, 4000)),
    "checkin_syncmesh": ("CHECKIN_SYNCMESH", (800, 1200)),
    "checkin_state": ("CHECKIN_STATE", (270, 330)),
    "checkin_drivers": ("CHECKIN_DRIVERS", (80000, 90000)),
}


def _runtime_sha256(runtime: str, agent) -> str:
    # a custom download url is the operator's responsibility
    if agent is None or getattr(settings, f"INSTALL_{runtime.upper()}_URL", ""):
        return ""
    version = getattr(settings, f"INSTALL_{runtime.upper()}_VERSION", "")
    digests = RUNTIME_SHA256[runtime].get(version, {})
    return digests.get(f"{agent.plat}/{agent.goarch}", "")


def _choco_pin() -> tuple[str, str]:
    sha256 = _dist_sha256(CHOCO_SCRIPT)
    if not sha256:
        return "", ""
    # the server's own /agentdist, also with a separate agent download host
    return f"{local_agents_dist_url()}/{CHOCO_SCRIPT}", sha256


def get_agent_config(agent=None) -> AgentCheckInConfig:
    intervals = {
        key: random.randint(*getattr(settings, name, default))
        for key, (name, default) in _INTERVALS.items()
    }
    choco_url, choco_sha256 = _choco_pin()

    def opt(name, default=""):
        return getattr(settings, name, default)

    return AgentCheckInConfig(
        **intervals,
        limit_data=opt("LIMIT_DATA", False),
        install_nushell=opt("INSTALL_NUSHELL", False),
        install_nushell_version=opt("INSTALL_NUSHELL_VERSION"),
        install_nushell_url=opt("INSTALL_NUSHELL_URL"),
        install_nushell_sha256=_runtime_sha256("nushell", agent),
        nushell_enable_config=opt("NUSHELL_ENABLE_CONFIG", False),
        install_deno=opt("INSTALL_DENO", False),
        install_deno_version=opt("INSTALL_DENO_VERSION"),
        install_deno_url=opt("INSTALL_DENO_URL"),
        install_deno_sha256=_runtime_sha256("deno", agent),
        deno_default_permissions=opt("DENO_DEFAULT_PERMISSIONS"),
        choco_install_url=choco_url,
        choco_install_sha256=choco_sha256,
    )
