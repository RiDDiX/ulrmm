# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import json
import random
import re
import shutil
import subprocess
from unittest.mock import patch

import pytest
from django.conf import settings
from model_bakery import baker
from nats.errors import NoRespondersError

from ulrmm.constants import AgentPlat
from ulrmm.test import ULRMMTestCase

from .posix import (
    PACKAGE_MANAGERS,
    POSIX_SCRIPT_TIMEOUTS,
    PROTECTED_REMOVE_TARGETS,
    REMOVABLE_SOURCES,
    SCRIPT_ENV_VARS,
    SCRIPT_PATH,
    SEVERITIES,
    build_script_payload,
    get_packages_script,
    is_valid_guid,
    is_protected_remove_target,
    is_valid_remove_target,
    parse_packages_output,
    run_packages_script,
)

FIXTURES = settings.BASE_DIR / "ulrmm" / "test_data" / "posix"
FIXTURE_FILES = sorted(FIXTURES.glob("*.txt"))

SOFTWARE_KEYS = {
    "name",
    "version",
    "publisher",
    "install_date",
    "size",
    "source",
    "location",
    "uninstall",
}
UPDATE_KEYS = {
    "guid",
    "kb",
    "title",
    "severity",
    "categories",
    "kb_article_ids",
    "description",
    "manager",
    "name",
    "arch",
    "current",
    "new",
}
DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \+0000 UTC")
SIZE_RE = re.compile(r"\d+ B|\d+\.\d (kB|MB|GB|TB)")

VALID_GUIDS = [
    "apt:libc6:amd64:2.36-9+deb12u7",
    "apt:libstdc++6:amd64:12.2.0-14",
    "dnf:openssl-libs:x86_64:1:3.0.7-25.el9_3",
    "yum:bash:x86_64:4.2.46-35.el7_9",
    "zypper:libcurl4:x86_64:8.14.1-150600.4.40.1",
    "pacman:archlinux-keyring:any:20260909-1",
    "apk:libssl3:x86_64:3.5.8-r0",
    "flatpak:org.mozilla.firefox:x86_64:129.0",
    "snap:core22::20240809",
    "brew:python@3.12::3.12.6",
    "brew-cask:google-chrome::127.0.6533.89,1",
    "softwareupdate:macOS Sonoma 14.6.1-23G93::14.6.1",
    "softwareupdate:Command Line Tools for Xcode (15.3)-15.3::15.3",
    "pkg:sudo::1.9.17p2_2",
    "pkg:py311-setuptools::63.1.0_3",
    "pkg:openjdk17::17.0.16+8.1,1",
]
INVALID_GUIDS = [
    "",
    "-rf",
    "apt:-rf::1",
    "apt:--reinstall:amd64:1",
    "dnf:-y:x86_64:1",
    "softwareupdate:-i::1",
    "softwareupdate: leading::1",
    "softwareupdate:a;reboot::1",
    "softwareupdate:a$(id)::1",
    "rpm:bash:x86_64:1",
    "apt:bash",
    "apt:bash:amd64",
    "apt:::1",
    "apt:foo bar::1",
    "apt:foo*::1",
    "apt:foo[a]::1",
    "apt:/tmp/evil.deb::1",
    "apt:../evil::1",
    "apt:foo=1.0::1",
    "apt:foo;id::1",
    "apt:foo\n::1",
    "apt:foo\t::1",
    "apt:foo:amd64:1\n",
    "apt:foo:am-d64:1",
    "apt:foo:amd64:1 2",
    "apt:foo:amd64:$(id)",
    "apt:sha1:" + "a" * 40,
    "apt:" + "a" * 260 + "::1",
]


def fixture_text(name: str) -> str:
    return (FIXTURES / name).read_text()


def test_fixtures_present():
    names = {p.stem for p in FIXTURE_FILES}
    for distro in ("debian12", "ubuntu2404", "fedora41", "rocky9", "arch", "leap156"):
        assert f"{distro}_inventory" in names
        assert f"{distro}_scan" in names
    assert {"alpine320_inventory", "alpine322_scan", "macos_refresh"} <= names


@pytest.mark.parametrize("path", FIXTURE_FILES, ids=lambda p: p.stem)
def test_parse_fixture(path):
    stem = path.stem
    parsed = parse_packages_output(path.read_text())

    if "inventory" in stem or "refresh" in stem:
        assert len(parsed.software) > 0
    if ("scan" in stem or "refresh" in stem) and "offline" not in stem:
        assert len(parsed.updates) > 0
        assert parsed.reboot_required is not None
    if "install" in stem:
        assert len(parsed.install_results) > 0
        assert parsed.reboot_required is not None
    if "offline" in stem:
        assert parsed.errors
        assert not parsed.updates
    else:
        assert not parsed.errors

    for item in parsed.software:
        assert set(item.keys()) == SOFTWARE_KEYS
        assert item["name"]
        assert item["uninstall"] == ""
        assert item["install_date"] == "" or DATE_RE.fullmatch(item["install_date"])
        assert item["size"] == "" or SIZE_RE.fullmatch(item["size"])

    guids = [u["guid"] for u in parsed.updates]
    assert len(guids) == len(set(guids))
    for u in parsed.updates:
        assert set(u.keys()) == UPDATE_KEYS
        assert is_valid_guid(u["guid"]), u["guid"]
        assert u["severity"] in SEVERITIES + ("",)
        assert isinstance(u["severity"], str)
        assert "(version" not in u["title"].lower()
        assert len(u["kb"]) <= 100
        assert u["description"].startswith(f"{u['current']} -> {u['new']}")

    for r in parsed.install_results:
        assert is_valid_guid(r["guid"])
        assert isinstance(r["exit_code"], int)


def test_parse_debian():
    parsed = parse_packages_output(fixture_text("debian12_refresh.txt"))
    bash = next(i for i in parsed.software if i["name"] == "bash")
    assert bash["source"] == "dpkg"
    assert bash["publisher"]
    assert SIZE_RE.fullmatch(bash["size"])
    assert parsed.reboot_required is False

    u = parsed.updates[0]
    assert u["manager"] == "apt"
    assert u["severity"] == "Important"
    assert u["categories"] == ["oldstable-security"]
    assert u["guid"] == f"apt:{u['name']}:amd64:{u['new']}"
    assert u["description"] == f"{u['current']} -> {u['new']} (oldstable-security)"


def test_parse_ubuntu_security_and_regular():
    parsed = parse_packages_output(fixture_text("ubuntu2404_scan.txt"))
    severities = {u["categories"][0]: u["severity"] for u in parsed.updates}
    assert severities.get("noble-security") == "Important"
    assert severities.get("noble-updates", "") == ""


def test_parse_rocky_updateinfo():
    parsed = parse_packages_output(fixture_text("rocky9_scan.txt"))
    assert {u["manager"] for u in parsed.updates} == {"dnf"}
    assert {"Important", "Moderate"} <= {u["severity"] for u in parsed.updates}
    security = [u for u in parsed.updates if u["categories"] == ["security"]]
    assert security
    for u in security:
        assert u["severity"] in SEVERITIES
        assert all(a.startswith("RL") for a in u["kb_article_ids"])

    inv = parse_packages_output(fixture_text("rocky9_inventory.txt"))
    assert all(i["source"] == "rpm" for i in inv.software)
    assert all(DATE_RE.fullmatch(i["install_date"]) for i in inv.software)


def test_parse_fedora_dnf5():
    parsed = parse_packages_output(fixture_text("fedora41_scan.txt"))
    xz = next(u for u in parsed.updates if u["name"] == "xz")
    assert xz["arch"] == "x86_64"
    assert xz["new"].startswith("1:")
    assert xz["guid"] == f"dnf:xz:x86_64:{xz['new']}"
    assert xz["severity"] == ""
    assert xz["categories"] == ["bugfix"]
    assert xz["kb_article_ids"][0].startswith("FEDORA-")


def test_parse_zypper_patches():
    parsed = parse_packages_output(fixture_text("leap156_scan.txt"))
    curl = next(u for u in parsed.updates if u["name"] == "curl")
    assert curl["manager"] == "zypper"
    assert curl["severity"] == "Important"
    assert curl["categories"] == ["security"]
    assert len(curl["kb_article_ids"]) > 1


def test_parse_install_results():
    parsed = parse_packages_output(fixture_text("debian12_install.txt"))
    by_guid = {r["guid"]: r for r in parsed.install_results}
    assert by_guid["apt:libpcre2-8-0:amd64:10.42-1+deb12u1"]["exit_code"] == 0
    assert by_guid["apk:musl:x86_64:1.2.5-r11"]["exit_code"] == 127

    failed = parse_packages_output(fixture_text("debian12_install_failed.txt"))
    assert failed.install_results[0]["exit_code"] == 100
    assert "Unable to locate package" in failed.install_results[0]["message"]


def test_parse_macos():
    parsed = parse_packages_output(fixture_text("macos_refresh.txt"))
    apps = {i["name"]: i for i in parsed.software if i["source"] == "app"}
    assert apps["Google Chrome"]["publisher"] == "Google LLC"
    assert apps["Google Chrome"]["install_date"] == "2024-08-01 10:02:33 +0000 UTC"
    assert apps["Google Chrome"]["location"] == "/Applications/Google Chrome.app"
    assert apps["Safari"]["publisher"] == "Apple"
    assert apps["Legacy Tool"]["version"] == ""
    assert {"brew", "brew-cask"} <= {i["source"] for i in parsed.software}

    updates = {u["guid"]: u for u in parsed.updates}
    sonoma = updates["softwareupdate:macOS Sonoma 14.6.1-23G93::14.6.1"]
    assert sonoma["severity"] == "Important"
    assert sonoma["categories"] == ["macOS"]
    assert updates["softwareupdate:macOS Sequoia 15.0-24A335::15.0"]["severity"] == ""
    assert "brew:python@3.12::3.12.6" in updates
    assert "brew-cask:firefox::129.0" in updates
    # pinned formulae are not offered
    assert not any(u["name"] == "node" for u in parsed.updates)

    installed = parse_packages_output(fixture_text("macos_install.txt"))
    assert installed.reboot_required is True
    assert {r["exit_code"] for r in installed.install_results} == {0, 127}


def test_parse_garbage():
    empty = parse_packages_output("")
    assert parse_packages_output(None) == empty  # type: ignore
    assert parse_packages_output(b"U\tapt") == empty  # type: ignore

    junk = "\n".join(
        [
            "U",
            "U\t",
            "U\tbogus\tname\tx86_64\t1\t2\tCritical\t\t\t",
            "U\tapt\t\tamd64\t1\t2",
            "S",
            "S\tdpkg\t\t1",
            "S\tdpkg\tfoo\t1\tbar\t12x\t-5\t",
            "S\tdpkg\tbig\t1\t\t99999999999999999999\t999999999999\t",
            "R\t2",
            "R",
            "I\tapt:foo::1\tabc\tmsg",
            "I\tapt:foo::1",
            "E",
            "J\tBEGIN",
            "{not json",
            "J\tEND",
            "J\tBEGIN",
            '{"SPApplicationsDataType": [1, "x", {"_name": 5}, {"_name": "A",'
            ' "signed_by": [7], "lastModified": 3}]}',
            "J\tEND",
            "J\tBEGIN",
            "[]",
            "J\tEND",
            "J\tBEGIN",
            '{"SPApplicationsDataType": [{"_name": "Unterminated"}]}',
        ]
    )
    parsed = parse_packages_output(junk)
    assert parsed.updates == []
    assert parsed.reboot_required is None
    assert parsed.install_results == []
    assert parsed.errors == []
    names = {i["name"]: i for i in parsed.software}
    assert set(names) == {"foo", "big", "A"}
    assert names["foo"]["size"] == names["foo"]["install_date"] == ""
    assert names["big"]["install_date"] == ""
    assert names["A"]["install_date"] == ""

    rng = random.Random(1234)
    alphabet = 'SUIREJ\t\t\t\n:-_ .()0123456789abcdefBEGINEND{}[]"\r\x00 é'
    for _ in range(200):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 400)))
        parse_packages_output(text)


def test_parse_source_package():
    parsed = parse_packages_output(
        "\n".join(
            [
                "S\tdpkg\topenssh-server\t1:10.0p1-7+deb13u4\tDebian OpenSSH Maintainers"
                " <debian-ssh@lists.debian.org>\t3511296\t1791364831\t\topenssh"
                "\t1:10.0p1-7+deb13u4",
                "S\tdpkg\tbsdutils\t1:2.41.5-0+deb13u1\tChris Hofstaedtler"
                " <zeha@debian.org>\t410624\t1787529600\t\tutil-linux"
                "\t2.41.5-0+deb13u1",
                "S\trpm\topenssh-clients\t9.9p1-12.el9_8.alma.1\tAlmaLinux\t2816074"
                "\t1791364862\t\topenssh\t9.9p1-12.el9_8.alma.1",
                "S\tapk\topenssh-server\t10.0_p1-r10\tNatanael Copa"
                " <ncopa@alpinelinux.org>\t2192232\t\t\topenssh\t10.0_p1-r10",
                # no source package on this line (old script, or the manager has none)
                "S\tdpkg\tcurl\t8.14.1-2\t\t\t\t",
                "S\tpacman\tbash\t5.3.3-2\t\t\t\t",
                "S\tapk\tbusybox\t1.37.0-r20\t\t\t\t\t\t",
            ]
        )
    )
    items = {(i["source"], i["name"]): i for i in parsed.software}
    sources = {
        key: (item["source_name"], item["source_version"])
        for key, item in items.items()
        if set(item) == SOFTWARE_KEYS | {"source_name", "source_version"}
    }
    assert sources == {
        ("dpkg", "openssh-server"): ("openssh", "1:10.0p1-7+deb13u4"),
        ("dpkg", "bsdutils"): ("util-linux", "2.41.5-0+deb13u1"),
        ("rpm", "openssh-clients"): ("openssh", "9.9p1-12.el9_8.alma.1"),
        ("apk", "openssh-server"): ("openssh", "10.0_p1-r10"),
    }
    for key in (("dpkg", "curl"), ("pacman", "bash"), ("apk", "busybox")):
        assert set(items[key]) == SOFTWARE_KEYS
    assert items["dpkg", "bsdutils"]["version"] == "1:2.41.5-0+deb13u1"
    assert items["dpkg", "openssh-server"]["install_date"]


def test_parse_update_details():
    long_name = "a" * 300
    long_version = "1." * 130
    parsed = parse_packages_output(
        "\n".join(
            [
                "U\tapt\tfoo\tamd64\t1.0\t1.1\tCritical\t\t\t",
                "U\tapt\tfoo\tamd64\t1.0\t1.1\tLow\t\t\t",
                "U\tdnf\tbar\tx86_64\t1\t2\tcritical\t\tA-1,,A-2\t",
                f"U\tapt\t{long_name}\tamd64\t1\t2\t\t\t\t",
                f"U\tflatpak\tlong.version\tx86_64\t1\t{long_version}\t\t\t\t",
                "U\tsoftwareupdate\tTool (Version 2)\t\t\t2\t\t\t\t",
                "U\tapk\ttruncated\tx86_64",
                "U\tapk\tshort\tx86_64\t1\t2",
                "R\t0",
                "R\t1",
            ]
        )
    )
    updates = {u["name"]: u for u in parsed.updates}
    assert len(parsed.updates) == 4
    assert "truncated" not in updates
    assert updates["foo"]["severity"] == "Critical"
    assert updates["foo"]["description"] == "1.0 -> 1.1"
    assert updates["bar"]["severity"] == ""
    assert updates["bar"]["kb_article_ids"] == ["A-1", "A-2"]
    # too long for a guid: skipped and reported, not stored under a guid it cannot install
    assert long_name not in updates
    assert "long.version" not in updates
    assert parsed.errors == [
        f"apt-skipped: update identifier too long for {'a' * 100}",
        "flatpak-skipped: update identifier too long for long.version",
    ]
    assert "(version" not in updates["Tool (Version 2)"]["title"].lower()
    assert updates["short"]["guid"] == "apk:short:x86_64:2"
    assert updates["short"]["severity"] == ""
    assert parsed.reboot_required is True


def test_package_managers():
    assert PACKAGE_MANAGERS == (
        "apt",
        "dnf",
        "yum",
        "zypper",
        "pacman",
        "apk",
        "flatpak",
        "snap",
        "brew",
        "brew-cask",
        "softwareupdate",
        "pkg",
    )
    assert all(is_valid_guid(f"{m}:foo::1") for m in PACKAGE_MANAGERS)


def test_refresh_errors_use_own_keys():
    # a failed index refresh still leaves a usable update list, so it must not
    # be reported under a guid prefix
    parsed = parse_packages_output(fixture_text("debian12_scan_offline.txt"))
    keys = {e.split(":", 1)[0] for e in parsed.errors}
    assert keys == {"apt-update"}
    assert not keys & set(PACKAGE_MANAGERS)

    parsed = parse_packages_output(fixture_text("alpine320_scan_offline.txt"))
    assert {e.split(":", 1)[0] for e in parsed.errors} == {"apk-refresh"}

    parsed = parse_packages_output(fixture_text("fedora41_scan_offline.txt"))
    assert {e.split(":", 1)[0] for e in parsed.errors} == {"dnf"}


@pytest.mark.parametrize("guid", VALID_GUIDS)
def test_valid_guid(guid):
    assert is_valid_guid(guid)


@pytest.mark.parametrize("guid", INVALID_GUIDS + [None, 123])
def test_invalid_guid(guid):
    assert not is_valid_guid(guid)


@pytest.mark.parametrize(
    "plat,source,target",
    [
        (AgentPlat.LINUX, "dpkg", "libfoo:i386"),
        (AgentPlat.LINUX, "rpm", "python3-libs"),
        (AgentPlat.LINUX, "pacman", "archlinux-keyring"),
        (AgentPlat.LINUX, "apk", "libssl3"),
        (AgentPlat.LINUX, "flatpak", "org.mozilla.firefox"),
        (AgentPlat.LINUX, "snap", "firefox"),
        (AgentPlat.DARWIN, "brew", "python@3.12"),
        (AgentPlat.DARWIN, "brew-cask", "google-chrome"),
        (AgentPlat.DARWIN, "app", "/Applications/Visual Studio Code.app"),
    ],
)
def test_valid_remove_target(plat, source, target):
    assert source in REMOVABLE_SOURCES[plat]
    assert is_valid_remove_target(source, target, plat)


@pytest.mark.parametrize(
    "plat,source,target",
    [
        (AgentPlat.LINUX, "dpkg", "-rf"),
        (AgentPlat.LINUX, "rpm", "foo bar"),
        (AgentPlat.LINUX, "app", "/Applications/Thing.app"),
        (AgentPlat.DARWIN, "brew", "../thing"),
        (AgentPlat.DARWIN, "app", "/Applications/.Hidden.app"),
        (AgentPlat.DARWIN, "app", "/Applications/Nested/Thing.app"),
        (AgentPlat.DARWIN, "app", "/tmp/Thing.app"),
        (AgentPlat.DARWIN, "app", "/Applications/Bad\nName.app"),
    ],
)
def test_invalid_remove_target(plat, source, target):
    assert not is_valid_remove_target(source, target, plat)


def test_protected_remove_targets():
    assert "dpkg" in PROTECTED_REMOVE_TARGETS
    for name in (
        "ulrmm-agent",
        "bash",
        "libc6:amd64",
        "linux-image-6.1.0-1-amd64",
        "linux-generic-hwe-24.04",
        "linux-virt",
        "linux-edge",
        "linux-hardened",
        "linux-rt-lts",
        "kernel-modules",
        "core22",
        "flatpak",
    ):
        assert is_protected_remove_target(name)
    assert not is_protected_remove_target("curl")


def test_parse_remove_result():
    parsed = parse_packages_output("noise\nI\tdpkg:curl\t0\tok\n")
    assert parsed.install_results == [
        {"guid": "dpkg:curl", "exit_code": 0, "message": "ok"}
    ]


def test_script_file():
    code = get_packages_script()
    assert code.startswith("#!/bin/sh\n")
    assert "\r" not in code
    assert code == SCRIPT_PATH.read_text()
    assert all(len(line) < 16384 for line in code.splitlines())

    # root must not resolve commands through user writable directories first
    assert "\nPATH=/usr/sbin:/usr/bin:/sbin:/bin\n" in code
    assert "/usr/local" not in code.split("\nPATH=", 1)[1].split("\n", 1)[0]
    assert "PATH=/usr/sbin:/usr/bin:/sbin:/bin" in SCRIPT_ENV_VARS

    assert "apt-get -s remove --" in code
    assert "rpm -e --test --" in code
    assert "pacman -R --noconfirm --" in code
    assert 'apk info -e "$1"' in code
    assert "flatpak uninstall -y --noninteractive" in code
    assert "uninstall --formula" in code
    assert "uninstall --cask" in code
    for unsafe in (
        "allow-remove-essential",
        "--force-remove",
        "--ignore-dependencies",
        "pacman -Rc",
        "pacman -Rs",
        "pacman -Rdd",
    ):
        assert unsafe not in code


def script_function(name: str) -> str:
    return re.search(
        rf"^{name}\(\) \{{\n.*?^\}}\n", get_packages_script(), re.S | re.M
    ).group(0)


def run_awk(program: str, text: str, name: str | None = None) -> str:
    args = ["awk"] + (["-v", f"name={name}"] if name is not None else []) + [program]
    r = subprocess.run(args, input=text, capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


APT_SIM_HEADER = (
    "NOTE: This is only a simulation!\n"
    "Reading package lists...\n"
    "Building dependency tree...\n"
    "The following packages will be REMOVED:\n"
    "  curl libcurl4-doc\n"
    "0 upgraded, 0 newly installed, 2 to remove and 0 not upgraded.\n"
)


@pytest.mark.skipif(not shutil.which("awk"), reason="needs awk")
def test_script_remove_dpkg_counts_all_removals():
    count_prog, deps_prog = re.findall(
        r"awk (?:-v name=\"\$1\" )?'(.*?)'", script_function("remove_dpkg"), re.S
    )

    def counted(text):
        return int(run_awk(count_prog, text))

    single = APT_SIM_HEADER + "Remv curl [7.88.1-10+deb12u5]\n"
    assert counted(single) == 1
    assert run_awk(deps_prog, single, name="curl") == ""

    with_dependent = single + "Remv libcurl4-doc [7.88.1-10+deb12u5]\n"
    assert counted(with_dependent) == 2
    assert run_awk(deps_prog, with_dependent, name="curl") == "libcurl4-doc"

    # a package scheduled for purge is removed as well
    with_purge = single + "Purg libcurl4-doc [7.88.1-10+deb12u5]\n"
    assert counted(with_purge) == 2
    assert run_awk(deps_prog, with_purge, name="curl") == "libcurl4-doc"

    # arch qualified names are reported the way apt prints them
    arch = APT_SIM_HEADER + "Remv libfoo:i386 [1.2-3]\nRemv libbar [2.0]\n"
    assert counted(arch) == 2
    assert run_awk(deps_prog, arch, name="libfoo:i386") == "libbar"


@pytest.mark.skipif(not shutil.which("awk"), reason="needs awk")
def test_script_remove_apk_lists_required_by():
    program = re.search(r"awk '(.*?)'", script_function("remove_apk"), re.S).group(1)

    assert run_awk(program, "") == ""
    assert run_awk(program, "busybox-1.36.1-r29 is required by:\n") == ""
    assert (
        run_awk(
            program,
            "busybox-1.36.1-r29 is required by:\n"
            "alpine-base-3.20.0-r0\n"
            "libc-utils-0.7.2-r5\n",
        )
        == "alpine-base-3.20.0-r0, libc-utils-0.7.2-r5"
    )


@pytest.mark.skipif(not shutil.which("sh"), reason="needs /bin/sh")
@pytest.mark.parametrize(
    "zypper_rc,expected", [(0, "0"), (102, "0"), (103, "0"), (106, "0"), (104, "104")]
)
def test_script_remove_rpm_maps_zypper_codes(zypper_rc, expected):
    runner = (
        script_function("lastmsg")
        + script_function("remove_result")
        + script_function("remove_rpm")
        + "rpm() { return 0; }\n"
        + f"zypper() {{ return {zypper_rc}; }}\n"
        + 'T=$(mktemp -d)\nRPM=1 DNF= ZYPPER=1\nremove_rpm nginx\nrm -rf "$T"\n'
    )
    r = subprocess.run(["sh", "-c", runner], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    assert r.stdout.split("\t")[2] == expected


@pytest.mark.skipif(not shutil.which("sh"), reason="needs /bin/sh")
def test_script_remove_rpm_keeps_unused_dependencies():
    runner = (
        script_function("lastmsg")
        + script_function("remove_result")
        + script_function("remove_rpm")
        + "rpm() { return 0; }\n"
        + 'dnf() { printf \'%s\\n\' "$*" >"$T/args"; return 0; }\n'
        + "T=$(mktemp -d)\nRPM=1 DNF=dnf ZYPPER=\nremove_rpm nginx\n"
        + 'cat "$T/args"\nrm -rf "$T"\n'
    )
    r = subprocess.run(["sh", "-c", runner], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    assert (
        r.stdout.splitlines()[-1]
        == "-y --setopt=clean_requirements_on_remove=False remove nginx"
    )


@pytest.mark.skipif(
    not shutil.which("sh") or not shutil.which("awk"), reason="needs sh and awk"
)
def test_script_inventory_rpm_source_package(tmp_path):
    (tmp_path / "rpm").write_text(
        "openssl-libs\t1:3.5.5-6.el9_8\tAlmaLinux\t7483131\t1788346034"
        "\topenssl-3.5.5-6.el9_8.src.rpm\n"
        "python3\t3.9.25-7.el9_8.3\tAlmaLinux\t32836\t1788346035"
        "\tpython3.9-3.9.25-7.el9_8.3.src.rpm\n"
        "odd\t1-1\t(none)\t5\t6\t(none)\n"
        "gpg-pubkey\t1-2\t(none)\t0\t7\t(none)\n"
    )
    runner = (
        script_function("lastmsg")
        + script_function("err")
        + script_function("inv_rpm")
        + f'rpm() {{ cat "{tmp_path}/rpm"; }}\n'
        + 'T=$(mktemp -d)\ninv_rpm\nrm -rf "$T"\n'
    )
    r = subprocess.run(["sh", "-c", runner], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    assert [line.split("\t") for line in r.stdout.splitlines()] == [
        ["S", "rpm", "openssl-libs", "1:3.5.5-6.el9_8", "AlmaLinux", "7483131"]
        + ["1788346034", "", "openssl", "1:3.5.5-6.el9_8"],
        ["S", "rpm", "python3", "3.9.25-7.el9_8.3", "AlmaLinux", "32836"]
        + ["1788346035", "", "python3.9", "3.9.25-7.el9_8.3"],
        ["S", "rpm", "odd", "1-1", "", "5", "6", "", "", ""],
    ]


def test_remove_brew_limits_fit_script_timeout():
    limits = [
        int(n)
        for n in re.findall(r"brew_run ([0-9]+) ", script_function("remove_target"))
    ]
    assert limits
    # brew_run kills brew itself (limit, then 10s before KILL) before the agent
    # stops the whole script
    assert max(limits) + 60 <= POSIX_SCRIPT_TIMEOUTS["remove"]


@pytest.mark.skipif(
    not shutil.which("sh") or not shutil.which("awk"), reason="needs sh and awk"
)
def test_script_output_cap_keeps_json():
    code = get_packages_script()
    cap = re.search(r"^main \"\$@\" \| (awk '.*?')$", code, re.S | re.M).group(1)
    apps = {
        "SPApplicationsDataType": [
            {"_name": "Evil", "info": "x" * 9000, "path": "/Users/a/Evil.app"},
            {"_name": "Safari", "obtained_from": "apple", "version": "17.6"},
        ]
    }
    text = "\n".join(
        [
            f"S\tbrew\t{'b' * 9000}\t1\t\t\t\t",
            "J\tBEGIN",
            json.dumps(apps, indent=2),
            "J\tEND",
            f"E\tbrew\t{'e' * 9000}",
            "R\t0",
            "",
        ]
    )
    r = subprocess.run(
        ["sh", "-c", cap], input=text, capture_output=True, text=True, timeout=30
    )
    lines = r.stdout.split("\n")
    assert r.returncode == 0
    assert max(len(line) for line in lines) > 9000
    assert len(lines[0]) == 8000
    assert len(next(line for line in lines if line.startswith("E\t"))) == 8000

    parsed = parse_packages_output(r.stdout)
    assert [i["name"] for i in parsed.software if i["source"] == "app"] == [
        "Evil",
        "Safari",
    ]
    assert parsed.reboot_required is False


@pytest.mark.skipif(not shutil.which("sh"), reason="needs /bin/sh")
def test_script_guid_rules_match_python():
    code = get_packages_script()
    func = re.search(r"^valid_guid\(\) \{\n.*?^\}\n", code, re.S | re.M).group(0)
    # the script has no length limit
    guids = [g for g in VALID_GUIDS + INVALID_GUIDS if len(g) <= 255]
    guids += [f"{m}:foo::1" for m in PACKAGE_MANAGERS] + ["apt-update:foo::1"]
    runner = (
        func
        + 'for g in "$@"; do if valid_guid "$g"; then echo 1; else echo 0; fi; done'
    )
    r = subprocess.run(
        ["sh", "-c", runner, "sh", *guids], capture_output=True, text=True, timeout=30
    )
    assert [x == "1" for x in r.stdout.split()] == [is_valid_guid(g) for g in guids]


@pytest.mark.skipif(not shutil.which("sh"), reason="needs /bin/sh")
def test_script_remove_rules_match_python():
    code = get_packages_script()
    functions = re.search(
        r"^valid_remove_name\(\) \{\n.*?^\}\n\n^valid_remove_target\(\) \{\n.*?^\}\n",
        code,
        re.S | re.M,
    ).group(0)
    cases = [
        (AgentPlat.LINUX, "dpkg", "libfoo:i386"),
        (AgentPlat.LINUX, "rpm", "python3-libs"),
        (AgentPlat.LINUX, "dpkg", "foo:_bad"),
        (AgentPlat.LINUX, "app", "/Applications/Thing.app"),
        (AgentPlat.DARWIN, "brew", "python@3.12"),
        (AgentPlat.DARWIN, "app", "/Applications/Visual Studio Code.app"),
        (AgentPlat.DARWIN, "app", "/Applications/Nested/Thing.app"),
        (AgentPlat.DARWIN, "app", "/Applications/Bad\nName.app"),
        (AgentPlat.FREEBSD, "pkg", "py311-pip"),
        (AgentPlat.FREEBSD, "pkg", "-x"),
        (AgentPlat.FREEBSD, "dpkg", "curl"),
        (AgentPlat.LINUX, "pkg", "curl"),
    ]
    runner = (
        functions
        + 'while [ $# -ge 3 ]; do OS=$1; if valid_remove_target "$2" "$3"; '
        + "then echo 1; else echo 0; fi; shift 3; done"
    )
    uname = {AgentPlat.LINUX: "Linux", AgentPlat.DARWIN: "Darwin"}
    args = [
        value
        for plat, source, target in cases
        for value in (uname.get(plat, "FreeBSD"), source, target)
    ]
    result = subprocess.run(
        ["sh", "-c", runner, "sh", *args],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert [value == "1" for value in result.stdout.split()] == [
        is_valid_remove_target(source, target, plat) for plat, source, target in cases
    ]


@pytest.mark.skipif(not shutil.which("sh"), reason="needs /bin/sh")
def test_script_rejects_bad_arguments():
    for args in (
        [],
        ["bogus"],
        ["install"],
        ["scan", "extra"],
        ["install", "-rf"],
        ["install", "apt:--reinstall:amd64:1"],
        ["install", "apt:curl:amd64:1", "apt:-o::1"],
        ["remove"],
        ["remove", "dpkg"],
        ["remove", "dpkg", "curl", "extra"],
        ["remove", "dpkg", "-rf"],
        ["remove", "app", "/Applications/Thing.app"],
    ):
        r = subprocess.run(
            ["sh", str(SCRIPT_PATH), *args],
            capture_output=True,
            text=True,
            timeout=30,
            stdin=subprocess.DEVNULL,
        )
        assert r.returncode == 3, args
        assert r.stdout.startswith("E\tscript\t")
        assert r.stderr == ""


def test_build_script_payload():
    for mode, timeout in POSIX_SCRIPT_TIMEOUTS.items():
        payload = build_script_payload(mode)
        assert payload == {
            "func": "runscriptfull",
            "timeout": timeout,
            "script_args": [mode],
            "payload": {"code": get_packages_script(), "shell": "shell"},
            "run_as_user": False,
            "env_vars": [
                "LC_ALL=C",
                "LANG=C",
                "DEBIAN_FRONTEND=noninteractive",
                "NEEDRESTART_MODE=a",
                "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
            ],
            "nushell_enable_config": settings.NUSHELL_ENABLE_CONFIG,
            "deno_default_permissions": settings.DENO_DEFAULT_PERMISSIONS,
        }

    payload = build_script_payload("install", ["apt:curl:amd64:1", "dnf:bash:x86_64:2"])
    assert payload["script_args"] == [
        "install",
        "apt:curl:amd64:1",
        "dnf:bash:x86_64:2",
    ]

    with pytest.raises(ValueError):
        build_script_payload("uninstall")


class TestRunPackagesScript(ULRMMTestCase):
    def setUp(self):
        self.agent = baker.make_recipe("agents.online_agent", plat=AgentPlat.LINUX)

    @patch("agents.models.Agent.nats_cmd")
    def test_reply(self, nats_cmd):
        reply = {
            "stdout": fixture_text("debian12_scan.txt"),
            "stderr": "",
            "retcode": 0,
            "execution_time": 12.3,
            "id": 0,
        }
        nats_cmd.return_value = reply

        r = run_packages_script(self.agent, "scan")

        self.assertEqual(r, reply)
        nats_cmd.assert_called_once_with(build_script_payload("scan"), timeout=930)
        self.assertTrue(parse_packages_output(r["stdout"]).updates)

    @patch("agents.models.Agent.nats_cmd")
    def test_install_args(self, nats_cmd):
        nats_cmd.return_value = {"stdout": "", "stderr": "", "retcode": 3}
        guids = ["apt:curl:amd64:7.88.1-10+deb12u8"]

        run_packages_script(self.agent, "install", guids)

        payload = nats_cmd.call_args.args[0]
        self.assertEqual(payload["script_args"], ["install", *guids])
        self.assertEqual(nats_cmd.call_args.kwargs["timeout"], 3630)

    @patch("agents.models.Agent.nats_cmd")
    def test_timeout(self, nats_cmd):
        nats_cmd.return_value = "timeout"
        self.assertEqual(run_packages_script(self.agent, "inventory"), "timeout")

    @patch("agents.models.Agent.nats_cmd")
    def test_payload(self, nats_cmd):
        nats_cmd.return_value = {"stdout": "R\t0\n", "stderr": "", "retcode": 0}
        payload = build_script_payload("install", ["apt:curl:amd64:1"])
        payload["timeout"] = 100

        run_packages_script(self.agent, "install", payload=payload)

        nats_cmd.assert_called_once_with(payload, timeout=130)

    @patch("agents.models.Agent.nats_cmd")
    def test_never_raises(self, nats_cmd):
        nats_cmd.side_effect = NoRespondersError
        r = run_packages_script(self.agent, "scan")
        self.assertIsInstance(r, str)
        self.assertIn("no responders", r)

        nats_cmd.side_effect = RuntimeError("boom")
        self.assertEqual(run_packages_script(self.agent, "scan"), "boom")

        nats_cmd.side_effect = ValueError()
        self.assertEqual(run_packages_script(self.agent, "scan"), "ValueError")

        nats_cmd.reset_mock()
        self.assertEqual(run_packages_script(self.agent, "bogus"), "invalid mode bogus")
        nats_cmd.assert_not_called()


# --- FreeBSD (pkg) and TrueNAS SCALE -------------------------------------------


def test_freebsd_refresh_fixture():
    parsed = parse_packages_output(fixture_text("freebsd144_refresh.txt"))
    assert not parsed.errors
    assert parsed.reboot_required is False
    software = {i["name"]: i for i in parsed.software}
    assert set(software) == {
        "firstboot-freebsd-update",
        "jq",
        "oniguruma",
        "pkg",
        "sudo",
    }
    assert software["jq"]["source"] == "pkg"
    assert software["jq"]["publisher"] == "yuri@FreeBSD.org"
    assert software["jq"]["size"] == "1.3 MB"
    assert DATE_RE.fullmatch(software["jq"]["install_date"])

    [update] = parsed.updates
    assert update["guid"] == "pkg:sudo::1.9.17p2_2"
    assert is_valid_guid(update["guid"])
    assert update["description"] == "1.9.5 -> 1.9.17p2_2"
    # pkg audit lists sudo, so the update is a security one
    assert (update["severity"], update["categories"]) == ("Important", ["security"])

    assert list(parsed.audit) == ["sudo"]
    assert parsed.audit["sudo"]["version"] == "1.9.5"
    assert len(parsed.audit["sudo"]["issues"]) == 3


def test_pkg_audit_block_is_checked():
    for body in ("not json", "[]", '{"packages": []}'):
        parsed = parse_packages_output(f"A\tBEGIN\n{body}\nA\tEND\nR\t0\n")
        assert parsed.audit is None, body
    parsed = parse_packages_output('A\tBEGIN\n{"pkg_count":0}\nA\tEND\n')
    assert parsed.audit == {}
    odd = {"packages": {"a": {"version": "1"}, "b": {"version": "1", "issues": []}}}
    parsed = parse_packages_output(f"A\tBEGIN\n{json.dumps(odd)}\nA\tEND\n")
    assert parsed.audit == {"b": {"version": "1", "issues": []}}
    # no audit block: unknown, not "nothing vulnerable"
    assert parse_packages_output("R\t0\n").audit is None


def test_freebsd_sources():
    assert REMOVABLE_SOURCES["freebsd"] == ("pkg",)
    assert is_valid_remove_target("pkg", "py311-pip", AgentPlat.FREEBSD)
    assert not is_valid_remove_target("pkg", "py311-pip", AgentPlat.LINUX)
    for name in ("pkg", "FreeBSD-runtime", "FreeBSD-kernel-generic", "sudo"):
        assert is_protected_remove_target(name), name
    assert not is_protected_remove_target("jq")


@pytest.mark.skipif(
    not shutil.which("sh") or not shutil.which("awk"), reason="needs sh and awk"
)
def test_script_pkg_scan(tmp_path):
    # pkg version -vRl'<' as printed on the FreeBSD 14.4 VM, plus a port epoch
    (tmp_path / "version").write_text(
        "pkg-2.5.1                          <   needs updating (remote has 2.8.4)\n"
        "py311-foo-bar-3.0.15_1,1           <   needs updating (remote has 3.0.16,1)\n"
        "firstboot-freebsd-update-1.4       =   up-to-date with remote\n"
    )
    runner = (
        script_function("lastmsg")
        + script_function("err")
        + script_function("scan_pkg")
        + f'pkg() {{ [ "$1" = version ] && cat "{tmp_path}/version"; return 0; }}\n'
        + 'T=$(mktemp -d)\nPKG=pkg\nscan_pkg\nrm -rf "$T"\n'
    )
    r = subprocess.run(["sh", "-c", runner], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    assert [line.split("\t") for line in r.stdout.splitlines()] == [
        ["U", "pkg", "pkg", "", "2.5.1", "2.8.4", "", "", "", ""],
        ["U", "pkg", "py311-foo-bar", "", "3.0.15_1,1", "3.0.16,1", "", "", "", ""],
    ]


@pytest.mark.skipif(
    not shutil.which("sh") or not shutil.which("awk"), reason="needs sh and awk"
)
def test_script_pkg_remove_refuses_dependents(tmp_path):
    # pkg delete -n oniguruma on the FreeBSD 14.4 VM, jq depends on it
    (tmp_path / "dry").write_text(
        "Checking integrity... done (0 conflicting)\n"
        "Deinstallation has been requested for the following 2 packages "
        "(of 0 packages in the universe):\n\n"
        "Installed packages to be REMOVED:\n\tjq: 1.8.2\n\toniguruma: 6.9.10\n\n"
        "Number of packages to be removed: 2\n"
    )
    runner = (
        script_function("lastmsg")
        + script_function("remove_result")
        + script_function("remove_pkg")
        + 'pkg() { printf \'%s\\n\' "$*" >>"$T/calls"; '
        + f'[ "$2" = -n ] && cat "{tmp_path}/dry"; return 0; }}\n'
        + 'T=$(mktemp -d)\nPKG=pkg\nremove_pkg "$1"\ncat "$T/calls"\nrm -rf "$T"\n'
    )

    def run(name):
        r = subprocess.run(
            ["sh", "-c", runner, "sh", name],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert r.returncode == 0, r.stderr
        return r.stdout.splitlines()

    assert run("oniguruma") == [
        "I\tpkg:oniguruma\t1\trefused: would also remove: jq",
        "delete -n -- oniguruma",
    ]
    (tmp_path / "dry").write_text(
        "Installed packages to be REMOVED:\n\tjq: 1.8.2\n\n"
        "Number of packages to be removed: 1\n"
    )
    assert run("jq") == [
        "I\tpkg:jq\t0\tok",
        "delete -n -- jq",
        "delete -y -- jq",
    ]


@pytest.mark.skipif(not shutil.which("sh"), reason="needs /bin/sh")
def test_script_truenas_refuses_changes(tmp_path):
    (tmp_path / "dpkg").write_text(
        "ii \tcurl\t7.88.1-10\tDebian\t500\tcurl\t7.88.1-10\n"
    )
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "dpkg-query").write_text(f'#!/bin/sh\ncat "{tmp_path}/dpkg"\n')
    (bindir / "dpkg-query").chmod(0o755)
    runner = (
        script_function("has")
        + script_function("err")
        + script_function("lastmsg")
        + script_function("inv_dpkg")
        + script_function("truenas_main")
        + 'MANAGED="package updates are managed by TrueNAS"\n'
        + f'PATH="{bindir}:$PATH"\n'
        + 'T=$(mktemp -d)\nTAB=$(printf "\\t")\nMODE=$1\nshift\n'
        + 'truenas_main "$@"\nrm -rf "$T"\n'
    )

    def run(*args):
        r = subprocess.run(
            ["sh", "-c", runner, "sh", *args],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert r.returncode == 0, r.stderr
        return r.stdout.splitlines()

    assert run("scan") == ["E\tapt\tpackage updates are managed by TrueNAS"]
    assert run("install", "apt:curl:amd64:8", "apt:jq:amd64:1") == [
        "I\tapt:curl:amd64:8\t1\tpackage updates are managed by TrueNAS",
        "I\tapt:jq:amd64:1\t1\tpackage updates are managed by TrueNAS",
    ]
    assert run("remove", "dpkg", "curl") == [
        "I\tdpkg:curl\t1\tpackage updates are managed by TrueNAS"
    ]
    # inventory and refresh read dpkg; without an R line the update list stays
    for mode in ("inventory", "refresh"):
        parsed = parse_packages_output("\n".join(run(mode)))
        assert [i["name"] for i in parsed.software] == ["curl"]
        assert parsed.reboot_required is None

    script = get_packages_script()
    assert script_function("is_truenas") == (
        "is_truenas() {\n    [ -e /data/manifest.json ] && [ -e /usr/bin/midclt ]\n}\n"
    )
    assert re.search(r"^main\(\) \{\n    if is_truenas; then", script, re.M)


@pytest.mark.skipif(
    not shutil.which("sh") or not shutil.which("awk"), reason="needs sh and awk"
)
def test_script_output_cap_keeps_audit_json():
    code = get_packages_script()
    cap = re.search(r"^main \"\$@\" \| (awk '.*?')$", code, re.S | re.M).group(1)
    audit = {"packages": {"a": {"version": "1", "issues": [{"x": "y" * 9000}]}}}
    text = f"A\tBEGIN\n{json.dumps(audit)}\nA\tEND\nE\tpkg\t{'e' * 9000}\n"
    r = subprocess.run(
        ["sh", "-c", cap], input=text, capture_output=True, text=True, timeout=30
    )
    parsed = parse_packages_output(r.stdout)
    assert parsed.audit == audit["packages"]
    assert len(parsed.errors[0]) < 8010
