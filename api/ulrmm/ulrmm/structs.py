# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import dataclasses
from typing import Any


class ULRMMStruct:
    def _to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass
class AgentCheckInConfig(ULRMMStruct):
    checkin_hello: int
    checkin_agentinfo: int
    checkin_winsvc: int
    checkin_pubip: int
    checkin_disks: int
    checkin_sw: int
    checkin_wmi: int
    checkin_syncmesh: int
    checkin_state: int
    checkin_drivers: int
    limit_data: bool
    install_nushell: bool
    install_nushell_version: str
    install_nushell_url: str
    install_nushell_sha256: str
    nushell_enable_config: bool
    install_deno: bool
    install_deno_version: str
    install_deno_url: str
    install_deno_sha256: str
    deno_default_permissions: str
    choco_install_url: str
    choco_install_sha256: str
