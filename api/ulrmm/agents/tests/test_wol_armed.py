# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from agents.models import Agent


def armed(wmi):
    return Agent(wmi_detail=wmi).wol_armed


def test_wol_armed():
    # agents before the health report
    assert armed(None) is None
    assert armed({"nics": [{"name": "eth0", "mac": "00:11:22:33:44:55"}]}) is None

    nics = [
        {"name": "Ethernet 2", "wol": "unsupported"},
        {"name": "WLAN 2", "wol": "on"},
    ]
    assert armed({"nics": nics, "health": {"v": 1}}) is True
    assert armed({"nics": nics[:1], "health": {"v": 1}}) is False
    # macOS: machine level
    assert armed({"nics": [{"name": "en0"}], "health": {"power": {"womp_ac": True}}})
    assert (
        armed({"nics": [{"name": "en0"}], "health": {"power": {"womp_ac": False}}})
        is False
    )
    # agent data is untrusted
    assert armed({"nics": "x", "health": {"power": "on"}}) is False
    assert armed({"nics": [None, 1, {"wol": ["on"]}], "health": []}) is None
    assert armed("garbage") is None
