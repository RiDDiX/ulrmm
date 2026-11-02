# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import ipaddress
from datetime import datetime
from typing import Any, List
from zoneinfo import ZoneInfo


def as_tz(value: datetime, tz: str, format: str = "%b %d %Y, %I:%M %p") -> str:
    if value.tzinfo is None:
        raise ValueError("as_tz needs a datetime with a time zone")
    return value.astimezone(ZoneInfo(tz)).strftime(format)


def local_ips(wmi_detail: Any) -> List[str]:
    ips: List[str] = []
    try:
        adapters = wmi_detail["network_config"]
        for adapter in adapters:
            try:
                addresses = next(
                    entry["IPAddress"]
                    for entry in adapter
                    if isinstance(entry, dict) and "IPAddress" in entry
                )
            except (StopIteration, TypeError):
                continue
            if not addresses:
                continue
            for address in addresses:
                if not isinstance(address, str):
                    continue
                try:
                    ipaddress.IPv4Address(address)
                except ValueError:
                    continue
                ips.append(address)
    except Exception:
        pass
    return ips
