# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import copy

import pytest

from checks.health import (
    ERROR,
    FAILING,
    MIN_RUN_INTERVAL,
    PASSING,
    WARNING,
    evaluate,
    is_virtual,
    run_interval,
)

# shapes as measured on the fleet (2026-09-24)
RIDDIX_PC = {
    "v": 1,
    "errors": [],
    "power": {"s3": True, "modern_standby": False},
    "av": [
        {
            "name": "Windows Defender",
            "enabled": False,
            "up_to_date": True,
            "src": "wsc",
        },
        {"name": "ESET Security", "enabled": True, "up_to_date": True, "src": "wsc"},
    ],
    "defender": {
        "mode": "Not running",
        "av": False,
        "rtp": False,
        "sig_age_days": None,
    },
    "firewall": {
        "enabled": True,
        "products": [{"name": "ESET Firewall", "enabled": True}],
        "profiles": {"domain": True, "private": True, "public": True},
    },
    "disks": [
        {
            "name": "Samsung SSD 9100 PRO 2TB",
            "bus": "nvme",
            "health": "ok",
            "smart": "unknown",
            "temp_c": 37,
            "temp_warn_c": 84,
        },
        {
            "name": "Samsung SSD 860 EVO 1TB",
            "bus": "sata",
            "health": "ok",
            "smart": "unknown",
            "temp_c": None,
            "poh": 19312,
        },
    ],
    "battery": None,
    "temps": [],
}

PC_WZ_HA = {
    "v": 1,
    "av": [
        {"name": "Windows Defender", "enabled": True, "up_to_date": True, "src": "wsc"}
    ],
    "defender": {"mode": "Normal", "av": True, "rtp": True, "sig_age_days": 0},
    "firewall": {"enabled": True, "products": []},
}

MAC = {
    "v": 1,
    "power": {"womp_ac": True, "womp_batt": False},
    "av": [{"name": "XProtect", "enabled": True, "src": "xprotect", "version": "5360"}],
    "firewall": {"enabled": True, "products": []},
    "disks": [
        {"name": "APPLE SSD AP0512Z", "bus": "nvme", "health": "ok", "smart": "passed"}
    ],
    "battery": {"max_capacity_pct": 100, "cycles": 40, "condition": "Good"},
    "thermal_pressure": 0,
}

LINUX = {
    "v": 1,
    "av": [],
    "firewall": {"enabled": False, "products": [{"name": "ufw", "enabled": False}]},
    "disks": [
        {
            "name": "Samsung 990",
            "bus": "nvme",
            "health": "ok",
            "smart": "passed",
            "temp_c": 52,
            "temp_warn_c": 82,
            "temp_crit_c": 85,
            "critical_warning": 0,
        },
        {"name": "/dev/sdd", "bus": "scsi", "health": "unknown", "smart": "standby"},
    ],
    "temps": [{"name": "coretemp Package id 0", "c": 76, "warn_c": 100, "crit_c": 100}],
}


def sec(plat, h, warn=3, err=7):
    return evaluate("security", plat, h, warn, err)


def hw(h, plat="linux", warn=20, err=30):
    return evaluate("hwhealth", plat, h, warn, err)


def test_eset_counts_not_defender():
    # Defender "Not running" next to ESET must not alert
    status, severity, text = sec("windows", RIDDIX_PC)
    assert (status, severity) == (PASSING, None)
    assert "ESET Security" in text


def test_windows_security_failures():
    h = copy.deepcopy(RIDDIX_PC)
    h["av"][1]["enabled"] = False
    assert sec("windows", h)[:2] == (FAILING, ERROR)

    h = copy.deepcopy(RIDDIX_PC)
    h["av"][1]["up_to_date"] = False
    status, severity, text = sec("windows", h)
    assert (status, severity) == (FAILING, WARNING) and "out of date" in text

    h = copy.deepcopy(PC_WZ_HA)
    h["firewall"]["enabled"] = False
    status, severity, text = sec("windows", h)
    assert (status, severity) == (FAILING, ERROR) and "firewall off" in text


@pytest.mark.parametrize(
    "age,expected",
    [
        (0, (PASSING, None)),
        (3, (PASSING, None)),
        (4, (FAILING, WARNING)),
        (7, (FAILING, WARNING)),
        (8, (FAILING, ERROR)),
    ],
)
def test_defender_signature_age(age, expected):
    h = copy.deepcopy(PC_WZ_HA)
    h["defender"]["sig_age_days"] = age
    assert sec("windows", h)[:2] == expected


def test_signature_age_ignored_when_defender_is_not_in_use():
    h = copy.deepcopy(RIDDIX_PC)
    h["defender"]["sig_age_days"] = 400
    assert sec("windows", h)[0] == PASSING


def test_windows_server_without_security_center():
    # third-party AV is invisible there: unknown, not off
    h = {
        "v": 1,
        "av": [],
        "defender": {"mode": "Not running", "av": False, "rtp": False},
        "firewall": {"enabled": True},
    }
    status, _, text = sec("windows", h)
    assert status == PASSING and "unknown" in text
    h["defender"] = {"mode": "Normal", "av": True, "rtp": False, "sig_age_days": 1}
    assert sec("windows", h)[:2] == (FAILING, ERROR)
    h["defender"]["rtp"] = True
    h["defender"]["sig_age_days"] = 9
    assert sec("windows", h)[:2] == (FAILING, ERROR)


def test_mac_and_linux_security():
    assert sec("darwin", MAC)[0] == PASSING
    h = copy.deepcopy(MAC)
    h["firewall"]["enabled"] = False
    assert sec("darwin", h)[:2] == (FAILING, ERROR)
    h = copy.deepcopy(MAC)
    h["av"] = []
    assert sec("darwin", h)[:2] == (FAILING, ERROR)
    # linux: reported, never alerted
    status, severity, text = sec("linux", LINUX)
    assert (status, severity) == (PASSING, None) and "firewall off" in text


def test_hwhealth_measured_hosts_pass():
    assert hw(LINUX)[0] == PASSING
    assert hw(RIDDIX_PC, "windows")[0] == PASSING
    assert hw(MAC, "darwin")[0] == PASSING


def test_hwhealth_disks_and_temps():
    h = copy.deepcopy(LINUX)
    h["disks"][0]["temp_c"] = 83
    assert hw(h)[:2] == (FAILING, WARNING)
    h["disks"][0]["temp_c"] = 85
    assert hw(h)[:2] == (FAILING, ERROR)

    h = copy.deepcopy(LINUX)
    h["disks"][0]["critical_warning"] = 4
    assert hw(h)[:2] == (FAILING, ERROR)

    h = copy.deepcopy(RIDDIX_PC)
    h["disks"][1]["health"] = "warning"
    assert hw(h, "windows")[:2] == (FAILING, WARNING)
    h["disks"][0]["smart"] = "failed"
    status, severity, text = hw(h, "windows")
    assert (status, severity) == (FAILING, ERROR) and text.startswith(
        "Samsung SSD 9100"
    )

    # no global limit: 99 C on a sensor with crit 100 is fine
    h = copy.deepcopy(LINUX)
    h["temps"][0]["c"] = 99
    assert hw(h)[0] == PASSING
    # bogus limits (hwmon max 65261 C) count as unknown
    h["temps"][0].update(c=70, warn_c=65261, crit_c=None)
    assert hw(h)[0] == PASSING


@pytest.mark.parametrize(
    "cap,expected",
    [
        (100, (PASSING, None)),
        (81, (PASSING, None)),
        (80, (FAILING, WARNING)),
        (71, (FAILING, WARNING)),
        (70, (FAILING, ERROR)),
    ],
)
def test_battery_wear(cap, expected):
    h = copy.deepcopy(MAC)
    h["battery"]["max_capacity_pct"] = cap
    assert hw(h, "darwin")[:2] == expected


def test_battery_condition_and_disabled_thresholds():
    h = copy.deepcopy(MAC)
    h["battery"]["condition"] = "Service Recommended"
    assert hw(h, "darwin")[:2] == (FAILING, WARNING)
    h = copy.deepcopy(MAC)
    h["battery"]["max_capacity_pct"] = 10
    assert hw(h, "darwin", warn=0, err=0)[0] == PASSING


@pytest.mark.parametrize(
    "report",
    [
        "x",
        [],
        {"av": []},
        {"v": "1"},
        {
            "v": 1,
            "av": "nope",
            "disks": {"a": 1},
            "firewall": [],
            "battery": 5,
            "temps": [None, 1, "x"],
        },
        {
            "v": 1,
            "av": [{"enabled": "yes", "name": 5}],
            "defender": {"sig_age_days": float("nan")},
        },
        {
            "v": 1,
            "disks": [{"temp_c": "hot", "temp_crit_c": [], "critical_warning": True}],
        },
        {"v": 1, "battery": {"max_capacity_pct": float("inf"), "condition": {"x": 1}}},
    ],
)
def test_untrusted_input_never_raises(report):
    for check_type in ("security", "hwhealth"):
        for plat in ("windows", "darwin", "linux", "weird"):
            status, severity, text = evaluate(check_type, plat, report, 3, 7)
            assert status in (PASSING, FAILING)
            assert isinstance(text, str) and len(text) <= 1000


def test_malformed_and_missing():
    assert evaluate("security", "windows", None, 3, 7) == (
        FAILING,
        WARNING,
        "no health report, agent update required",
    )
    assert (
        evaluate("hwhealth", "linux", {"no": "v"}, 20, 30)[2]
        == "malformed health report"
    )


def test_long_input_is_capped():
    h = {"v": 1, "disks": [{"name": "d" * 10_000, "health": "failing"}] * 1000}
    status, severity, text = hw(h)
    assert (status, severity) == (FAILING, ERROR)
    assert len(text) <= 1000


# what Agent.Health() sends when the collector overruns its 30 s
TIMED_OUT = {
    "v": 1,
    "errors": ["collection timed out"],
    "power": {},
    "av": None,
    "defender": None,
    "firewall": None,
    "platform": None,
    "disks": None,
    "battery": None,
    "temps": None,
    "thermal_pressure": None,
}


@pytest.mark.parametrize("plat", ["windows", "darwin", "linux"])
def test_timed_out_report_never_passes(plat):
    expected = (FAILING, WARNING, "health report incomplete: collection timed out")
    assert hw(TIMED_OUT, plat) == expected
    if plat == "linux":
        assert sec(plat, TIMED_OUT)[0] == PASSING
    else:
        # not "XProtect missing" on a Mac, not "OK" on Windows
        assert sec(plat, TIMED_OUT) == expected
    assert hw({"v": 1}, plat)[2] == "health report incomplete: no disks"


def test_partly_read_disks_never_pass():
    h = copy.deepcopy(RIDDIX_PC)
    h["disks"], h["errors"] = [], ["MSFT_PhysicalDisk: Exception occurred."]
    status, severity, text = hw(h, "windows")
    assert (status, severity) == (FAILING, WARNING)
    assert text == "not read: MSFT_PhysicalDisk: Exception occurred."

    h = copy.deepcopy(LINUX)
    h["disks"][0]["critical_warning"] = 4
    h["errors"] = ["smartctl --scan: signal: killed", "nvme1: no such device"]
    status, severity, text = hw(h)
    assert (status, severity) == (FAILING, ERROR)
    assert text.startswith("Samsung 990 failing; not read: smartctl --scan")

    h = copy.deepcopy(MAC)
    h["disks"], h["errors"] = [], ["system_profiler: exit status 1"]
    assert hw(h, "darwin")[:2] == (FAILING, WARNING)

    # permanent gaps and other sections do not fail the disk check
    h = copy.deepcopy(LINUX)
    h["errors"] = ["smartctl not installed", "GetPwrCapabilities: x", "FwPolicy2: y"]
    assert hw(h)[0] == PASSING


def test_missing_smartctl_is_named_when_no_disk_was_read():
    h = copy.deepcopy(LINUX)
    h["disks"], h["temps"], h["errors"] = [], [], ["smartctl not installed"]
    line = "disk health not read: smartctl is not installed"
    assert hw(h) == (PASSING, None, f"OK: 0 disk(s); {line}")
    freebsd = evaluate("hwhealth", "freebsd", h, 20, 30, lambda: "Supermicro X11")
    assert freebsd == (PASSING, None, f"OK: 0 disk(s); {line}")

    # the status rules stay, the line follows the problems
    h["temps"] = [{"name": "cpu", "c": 101, "warn_c": 90, "crit_c": 100}]
    assert hw(h) == (FAILING, ERROR, f"cpu 101 C at critical limit 100 C; {line}")

    # virtual machines have no disks of their own to read
    h["temps"] = []
    for vm in ("QEMU pc-q35-8.1", "VMware, Inc. VMware7,1", "BHYVE BHYVE"):
        assert evaluate("hwhealth", "linux", h, 20, 30, lambda: vm) == (
            PASSING,
            None,
            "OK: 0 disk(s)",
        )

    # a make and model that cannot be read counts as a physical host
    def unreadable():
        raise RuntimeError("database gone")

    assert evaluate("hwhealth", "linux", h, 20, 30, unreadable) == (
        PASSING,
        None,
        f"OK: 0 disk(s); {line}",
    )

    # disks read another way need no line
    h = copy.deepcopy(LINUX)
    h["errors"] = ["smartctl not installed"]
    assert hw(h)[2] == "OK: 2 disk(s)"


def test_is_virtual():
    for name in (
        "QEMU Standard PC (Q35 + ICH9, 2009)",
        "innotek GmbH VirtualBox",
        "Microsoft Corporation Virtual Machine",
        "Xen HVM domU",
        "Amazon EC2 t3.micro",
        "No Enclosure N/A",
        "Hetzner vServer",
        "DigitalOcean Droplet",
        "Nutanix AHV",
        "oVirt oVirt Node",
        "Alibaba Cloud Alibaba Cloud ECS",
        "Cloud Hypervisor cloud-hypervisor",
        "Red Hat RHEV Hypervisor",
    ):
        assert is_virtual(name), name
    for name in (
        "Dell Inc. OptiPlex 7090",
        "Nutanix NX-3060-G6",
        "",
        None,
        5,
        "error getting make/model",
    ):
        assert not is_virtual(name), name


def test_partly_read_security_never_passes():
    # Security Center failed on a workstation, ESET is invisible then
    h = copy.deepcopy(RIDDIX_PC)
    h["av"], h["errors"] = [], ["security center: Exception occurred."]
    status, severity, text = sec("windows", h)
    assert (status, severity) == (FAILING, WARNING)
    assert "not read: security center" in text

    h = copy.deepcopy(PC_WZ_HA)
    h["firewall"] = {"enabled": None, "products": []}
    h["errors"] = ["FwPolicy2: Exception occurred."]
    assert sec("windows", h) == (FAILING, WARNING, "firewall state unknown")

    h = copy.deepcopy(MAC)
    h["firewall"], h["errors"] = None, ["socketfilterfw: exit status 1"]
    assert sec("darwin", h) == (
        FAILING,
        WARNING,
        "health report incomplete: socketfilterfw: exit status 1",
    )

    # Defender is the AV in use but its status was not read: no signature age
    h = copy.deepcopy(PC_WZ_HA)
    h["defender"] = None
    assert sec("windows", h) == (FAILING, WARNING, "Defender status not read")


def test_run_interval():
    assert run_interval("security", 0, 120) == 900
    assert run_interval("hwhealth", 30, 120) == MIN_RUN_INTERVAL
    assert run_interval("hwhealth", 3600, 120) == 3600
    assert run_interval("cpuload", 0, 120) == 120
    assert run_interval("cpuload", 30, 120) == 30
