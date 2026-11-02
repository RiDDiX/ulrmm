# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Linux unattended-install answer files for the deployment builder.

One module per the builder interface (matrix.py merges TARGETS, views dispatch
by family). Formats: Ubuntu autoinstall, Debian preseed, Kickstart (RHEL/Rocky/
Alma 9 and 10, Fedora), AutoYaST (SLE/Leap 15), Agama (SLE/Leap 16), archinstall
(Arch, CachyOS, EndeavourOS) and the Batocera config and service files.

Every format installs the agent the same way: a first-boot systemd unit runs
the shared bootstrap script once after the network is up, then removes itself
and the token. Edition-specific install-time work (ssh, firewall, root lock)
runs in the answer file's post phase.
"""

import base64
import hashlib
import hmac
import re
import shlex
import string
import subprocess
from urllib.parse import urlparse
from xml.etree import ElementTree as ET

from django.conf import settings
from rest_framework import serializers

from deploy import signing, yamlish
from deploy.profile import prune_blank, serializer_defaults
from ulrmm.agent_ident import agent_ident

# ---------------------------------------------------------------------------
# seams: patched in tests and in the container validator (no DB, no S-PKG)


def _bootstrap(deployment) -> str:
    """The shared Linux bootstrap script (agent enrollment), from S-PKG."""
    from deploy.installers import bootstrap_sh

    return bootstrap_sh(deployment)


def _laps_account(site_id) -> "str | None":
    from laps.models import LapsPolicy

    policy = LapsPolicy.for_site(site_id)
    return policy.account if (policy and policy.enabled) else None


# ---------------------------------------------------------------------------
# targets

_FW_UFW = "ufw"
_FW_FIREWALLD = "firewalld"

# root file systems per distribution group, the first is the default; the
# Ubuntu autoinstall layouts only make ext4 and RHEL has no btrfs
_FILESYSTEMS = {
    "ubuntu": ["ext4"],
    "rhel": ["xfs", "ext4"],
    "rocky": ["xfs", "ext4"],
    "alma": ["xfs", "ext4"],
    "fedora": ["xfs", "ext4", "btrfs"],
    "sles": ["btrfs", "xfs", "ext4"],
    "leap": ["btrfs", "xfs", "ext4"],
}

# desktops per distribution: the package, task, group or pattern that
# installs each one; archinstall takes its profile name and greeter
_UBUNTU_DESKTOPS = {
    "gnome": "ubuntu-desktop",
    "kde": "kubuntu-desktop",
    "xfce": "xubuntu-desktop",
    "mate": "ubuntu-mate-desktop",
    "lxqt": "lubuntu-desktop",
    "budgie": "ubuntu-budgie-desktop",
}
_DESKTOPS = {
    "ubuntu-22.04": dict(_UBUNTU_DESKTOPS, cinnamon="cinnamon-desktop-environment"),
    "ubuntu-24.04": dict(_UBUNTU_DESKTOPS, cinnamon="ubuntucinnamon-desktop"),
    "ubuntu-26": dict(_UBUNTU_DESKTOPS, cinnamon="ubuntucinnamon-desktop"),
    "debian": {
        d: f"{d}-desktop"
        for d in ("gnome", "kde", "xfce", "cinnamon", "mate", "lxqt", "lxde")
    },
    # Server with GUI; RHEL and its rebuilds ship no other desktop
    "el": {"gnome": "graphical-server-environment"},
    "fedora": {
        "gnome": "workstation-product-environment",
        "kde": "kde-desktop-environment",
        "xfce": "xfce-desktop-environment",
        "cinnamon": "cinnamon-desktop-environment",
        "mate": "mate-desktop-environment",
        "lxqt": "lxqt-desktop-environment",
        "budgie": "budgie-desktop-environment",
        "sway": "sway-desktop-environment",
    },
    "leap-15": {"gnome": "gnome", "kde": "kde", "xfce": "xfce"},
    "leap-16": {"gnome": "gnome", "kde": "kde", "xfce": "xfce_wayland"},
    "sles-16": {"gnome": "gnome"},
    "arch": {
        "gnome": ("GNOME", "gdm"),
        "kde": ("KDE Plasma", "plasma-login-manager"),
        "xfce": ("Xfce4", "lightdm-gtk-greeter"),
        "cinnamon": ("Cinnamon", "lightdm-gtk-greeter"),
        "mate": ("Mate", "lightdm-gtk-greeter"),
        "lxqt": ("Lxqt", "sddm"),
        "budgie": ("Budgie", "lightdm-slick-greeter"),
        "sway": ("Sway", "lightdm-gtk-greeter"),
        "hyprland": ("Hyprland", "sddm"),
    },
}
# archinstall's profile and greeter plus the eos-packagelist profile that
# adds the EndeavourOS desktop packages
_DESKTOPS["endeavouros"] = {
    d: _DESKTOPS["arch"][d] + (eos,)
    for d, eos in (
        ("gnome", "GNOME-Desktop"),
        ("kde", "KDE-Desktop"),
        ("xfce", "XFCE4-Desktop"),
        ("cinnamon", "Cinnamon-Desktop"),
        ("mate", "MATE-Desktop"),
        ("lxqt", "LXQT-Desktop"),
        ("budgie", "Budgie-Desktop"),
    )
}
_DESKTOP_LABELS = {
    "none": "None (console only)",
    "gnome": "GNOME",
    "kde": "KDE Plasma",
    "xfce": "Xfce",
    "cinnamon": "Cinnamon",
    "mate": "MATE",
    "lxqt": "LXQt",
    "lxde": "LXDE",
    "budgie": "Budgie",
    "sway": "Sway",
    "hyprland": "Hyprland",
}

# ksver: the pykickstart handler the generator targets per branch
_KS = [
    ("rhel-9", "rhel", "RHEL 9", "RHEL9"),
    ("rhel-10", "rhel", "RHEL 10", "RHEL10"),
    ("rocky-9", "rocky", "Rocky Linux 9", "RHEL9"),
    ("rocky-10", "rocky", "Rocky Linux 10", "RHEL10"),
    ("alma-9", "alma", "AlmaLinux 9", "RHEL9"),
    ("alma-10", "alma", "AlmaLinux 10", "RHEL10"),
    ("fedora", "fedora", "Fedora", "F43"),
]


# official installer images; pinned point releases, so the links move with
# each ulrmm release
_LINKS_AS_OF = "2026-10-26"


def _dl(label, url, sums=None, size=None) -> dict:
    return {"label": label, "url": url, "sha256_url": sums, "size": size}


def _ubuntu(ver, point, desktop_point, released, eol, size, desktop_size):
    base = f"https://releases.ubuntu.com/{ver}/"
    sums = base + "SHA256SUMS"
    return {
        "release": {
            "lts": ver.endswith(".04") and int(ver[:2]) % 2 == 0,
            "released": released,
            "eol": eol,
            "status": "supported" if ver.endswith(".04") else "interim",
        },
        "downloads": [
            _dl(
                f"Server {point}",
                f"{base}ubuntu-{point}-live-server-amd64.iso",
                sums,
                size,
            ),
            _dl(
                f"Desktop {desktop_point}",
                f"{base}ubuntu-{desktop_point}-desktop-amd64.iso",
                sums,
                desktop_size,
            ),
        ],
    }


_FEDORA = "https://dl.fedoraproject.org/pub/fedora/linux/releases/44/"
_ROCKY = "https://dl.rockylinux.org/pub/rocky/"
_ALMA = "https://repo.almalinux.org/almalinux/"
_LEAP = "https://download.opensuse.org/distribution/leap/"
_ARCH_ISO = [
    _dl(
        "Arch Linux (latest)",
        "https://geo.mirror.pkgbuild.com/iso/latest/archlinux-x86_64.iso",
        "https://geo.mirror.pkgbuild.com/iso/latest/sha256sums.txt",
        "1.5 GiB",
    )
]


def _el(base, ver, sizes, dvd=""):
    """Minimal ISO, plus the DVD where it fits the 14 GiB library limit
    (the 9.x DVDs do not)."""
    iso = f"{base}{ver}/isos/x86_64/"
    name = "Rocky" if "rocky" in base else "AlmaLinux"
    out = [
        _dl(
            f"Minimal {ver}",
            f"{iso}{name}-{ver}-x86_64-minimal.iso",
            iso + "CHECKSUM",
            sizes[0],
        )
    ]
    if dvd:
        out.append(
            _dl(
                f"DVD {ver}",
                f"{iso}{name}-{ver}-x86_64-{dvd}.iso",
                iso + "CHECKSUM",
                sizes[1],
            )
        )
    return out


_DOWNLOADS = {
    "debian-12": [
        _dl(
            "Netinstall 12.15",
            "https://cdimage.debian.org/cdimage/archive/12.15.0/amd64/iso-cd/"
            "debian-12.15.0-amd64-netinst.iso",
            "https://cdimage.debian.org/cdimage/archive/12.15.0/amd64/iso-cd/"
            "SHA256SUMS",
            "677 MiB",
        )
    ],
    "debian-13": [
        _dl(
            "Netinstall 13.7",
            "https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/"
            "debian-13.7.0-amd64-netinst.iso",
            "https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/SHA256SUMS",
            "756 MiB",
        )
    ],
    "fedora": [
        _dl(
            "Server netinstall 44",
            f"{_FEDORA}Server/x86_64/iso/Fedora-Server-netinst-x86_64-44-1.7.iso",
            f"{_FEDORA}Server/x86_64/iso/Fedora-Server-44-1.7-x86_64-CHECKSUM",
            "1.1 GiB",
        ),
        _dl(
            "Server DVD 44",
            f"{_FEDORA}Server/x86_64/iso/Fedora-Server-dvd-x86_64-44-1.7.iso",
            f"{_FEDORA}Server/x86_64/iso/Fedora-Server-44-1.7-x86_64-CHECKSUM",
            "3.6 GiB",
        ),
        _dl(
            "Everything netinstall 44",
            f"{_FEDORA}Everything/x86_64/iso/"
            "Fedora-Everything-netinst-x86_64-44-1.7.iso",
            f"{_FEDORA}Everything/x86_64/iso/Fedora-Everything-44-1.7-x86_64-CHECKSUM",
            "1.1 GiB",
        ),
    ],
    "rocky-9": _el(_ROCKY, "9.8", ("2.6 GiB",)),
    "rocky-10": _el(_ROCKY, "10.2", ("1.9 GiB", "9.5 GiB"), "dvd1"),
    "alma-9": _el(_ALMA, "9.8", ("2.6 GiB",)),
    "alma-10": _el(_ALMA, "10.2", ("1.5 GiB", "9.4 GiB"), "dvd"),
    "leap-15": [
        _dl(
            f"{kind} 15.6",
            f"{_LEAP}15.6/iso/openSUSE-Leap-15.6-{kind}-x86_64-Current.iso",
            f"{_LEAP}15.6/iso/openSUSE-Leap-15.6-{kind}-x86_64-Current.iso.sha256",
            size,
        )
        for kind, size in (("DVD", "4.3 GiB"), ("NET", "261 MiB"))
    ],
    "leap-16": [
        _dl(
            "Offline installer 16.0",
            f"{_LEAP}16.0/offline/Leap-16.0-offline-installer-x86_64.install.iso",
            # only a sha512 file next to it
            None,
            "4.2 GiB",
        )
    ],
    "arch": _ARCH_ISO,
    # installed from the Arch ISO, not from the distributions' own media
    "cachyos": _ARCH_ISO,
    "endeavouros": _ARCH_ISO,
    "batocera": [
        _dl(
            "Batocera 43.1 x86_64",
            "https://mirrors.o2switch.fr/batocera/x86_64/stable/last/"
            "batocera-x86_64-43.1-20260529.img.gz",
            None,
            "4.0 GiB",
        )
    ],
}
# repositories the Arch helper adds on the live system before archinstall
# runs (pacstrap reads its pacman.conf and the install copies it), with the
# keyring and mirror list packages and the pinned signing key fingerprints
_ARCH_REPOS = {
    "cachyos": {
        "name": "cachyos",
        "server": "https://mirror.cachyos.org/repo/$arch/$repo",
        "siglevel": "",
        "mirrorlist": "cachyos-mirrorlist",
        "packages": ["cachyos-keyring", "cachyos-mirrorlist"],
        "keys": ["882DCFE48E2051D48E2562ABF3B607488DB35A47"],
    },
    # the database is unsigned, the packages are signed
    "endeavouros": {
        "name": "endeavouros",
        "server": "https://mirror.moson.org/endeavouros/repo/$repo/$arch",
        "siglevel": "PackageRequired",
        "mirrorlist": "endeavouros-mirrorlist",
        "packages": ["endeavouros-keyring", "endeavouros-mirrorlist"],
        "keys": [
            "8F43FC374CD4CEEA19CEE323E3D8752ACDF595A1",
            "286E73D3CB90A2368DE1B0B12B37DD3DB00531E8",
            "497AF50C92AD2384C56E1ACA003DB8B0CB23504F",
            "E0D16589967E1FE68EF8693E7EED78C58A63A62E",
            "0F20FADC599D1C46EB556455AED8858E4B9813F1",
            "C918B8CB65A96DFA48F1F2E6BC4423F58F260BAF",
            "8AD2DB862F3CA7B90B9CAF578B7B0A2203562CF6",
        ],
    },
}
_KERNELS = {
    "linux-cachyos": "CachyOS kernel",
    "linux-cachyos-lts": "CachyOS LTS kernel",
    "linux": "Arch Linux kernel",
}
_RELEASES = {
    "debian-12": {
        "lts": True,
        "released": "2023-06-10",
        "eol": "2028-06-30",
        "status": "supported",
    },
    "debian-13": {
        "lts": False,
        "released": "2025-08-09",
        "eol": "2028-08-09",
        "status": "supported",
    },
}


def _targets() -> list:
    out = []

    def add(tid, group, label, kind, tool, **extra):
        caps = {
            "ssh": extra.get("ssh", True),
            "firewall": extra.get("firewall", True),
            "luks": extra.get("luks", True),
            "lvm": extra.get("lvm", True),
            "registration": extra.get("registration", False),
            "mirror": extra.get("mirror", False),
            "proxy": extra.get("proxy", True),
            "device_required": extra.get("device_required", False),
            "extra_packages": extra.get("extra_packages", True),
            # a seed or full ISO can be built around the installer
            "iso_image": extra.get("iso_image", True),
        }
        filesystems = _FILESYSTEMS.get(group, ["ext4", "xfs", "btrfs"])
        defaults = {
            "layout": "direct" if not caps["lvm"] else "lvm",
            "filesystem": filesystems[0],
            "firewall": True,
            "ssh": True,
            "root_locked": True,
        }
        out.append(
            {
                "id": tid,
                "family": "linux",
                "group": group,
                "label": label,
                "formats": [kind],
                "capabilities": caps,
                "defaults": defaults,
                "notes": list(extra.get("notes", [])),
                # internal, dropped by matrix.py before the API if it wants to
                "kind": kind,
                "fw_tool": tool,
                "filesystems": filesystems,
                "desktops": extra.get("desktops", {}),
                "ksver": extra.get("ksver", ""),
                "product_id": extra.get("product_id", ""),
                "ubuntu_release": extra.get("ubuntu_release", ""),
                "kernels": extra.get("kernels", []),
            }
        )
        target = out[-1]
        if tid in _RELEASES or "release" in extra:
            target["release"] = extra.get("release") or _RELEASES[tid]
        downloads = extra.get("downloads") or _DOWNLOADS.get(tid)
        if downloads:
            target["downloads"] = downloads
            target["notes"].append(f"Official image links as of {_LINKS_AS_OF}.")

    add(
        "ubuntu-22.04",
        "ubuntu",
        "Ubuntu 22.04 LTS",
        "autoinstall",
        _FW_UFW,
        mirror=True,
        ubuntu_release="22.04",
        desktops=_DESKTOPS["ubuntu-22.04"],
        notes=["Delivered as NoCloud user-data with the autoinstall kernel argument."],
        **_ubuntu(
            "22.04",
            "22.04.5",
            "22.04.5",
            "2022-04-21",
            "2027-06-01",
            "2.0 GiB",
            "4.4 GiB",
        ),
    )
    add(
        "ubuntu-24.04",
        "ubuntu",
        "Ubuntu 24.04 LTS",
        "autoinstall",
        _FW_UFW,
        mirror=True,
        ubuntu_release="24.04",
        desktops=_DESKTOPS["ubuntu-24.04"],
        notes=["autoinstall.yaml on the installation media root."],
        **_ubuntu(
            "24.04",
            "24.04.5",
            "24.04.5.1",
            "2024-04-25",
            "2029-05-31",
            "3.8 GiB",
            "5.8 GiB",
        ),
    )
    for ver, point, released, eol, sizes in (
        ("26.04", "26.04.1", "2026-04-23", "2031-05-29", ("2.7 GiB", "6.0 GiB")),
        ("26.10", "26.10", "2026-10-15", "2027-07-15", ("2.7 GiB", "6.2 GiB")),
    ):
        lts = " LTS" if ver.endswith(".04") else ""
        add(
            f"ubuntu-{ver}",
            "ubuntu",
            f"Ubuntu {ver}{lts}",
            "autoinstall",
            _FW_UFW,
            mirror=True,
            ubuntu_release=ver,
            desktops=_DESKTOPS["ubuntu-26"],
            notes=["autoinstall.yaml on the installation media root."],
            **_ubuntu(ver, point, point, released, eol, *sizes),
        )
    add(
        "debian-12",
        "debian",
        "Debian 12 (bookworm)",
        "preseed",
        _FW_UFW,
        mirror=True,
        desktops=_DESKTOPS["debian"],
        notes=[
            "Preseeding is not verified by the installer; treat the file as a secret."
        ],
    )
    add(
        "debian-13",
        "debian",
        "Debian 13 (trixie)",
        "preseed",
        _FW_UFW,
        mirror=True,
        desktops=_DESKTOPS["debian"],
    )
    for tid, group, label, ksver in _KS:
        notes = []
        if ksver == "RHEL10":
            notes.append("RHEL 10 branch: no authconfig, module, vnc or %anaconda.")
        desktops = _DESKTOPS["fedora" if group == "fedora" else "el"]
        if group == "fedora":
            notes.append(
                "Desktops other than the ISO's own need the network repositories"
                " (Everything netinstall ISO)."
            )
        add(
            tid,
            group,
            label,
            "kickstart",
            _FW_FIREWALLD,
            ksver=ksver,
            desktops=desktops,
            notes=notes,
        )
    add(
        "sles-15",
        "sles",
        "SUSE Linux Enterprise 15",
        "autoyast",
        _FW_FIREWALLD,
        registration=True,
        notes=[
            "Needs a registration code to reach the SUSE repositories.",
            "No desktop: it needs the Desktop Applications module, which the"
            " answer file does not register.",
        ],
    )
    add(
        "leap-15",
        "leap",
        "openSUSE Leap 15",
        "autoyast",
        _FW_FIREWALLD,
        desktops=_DESKTOPS["leap-15"],
    )
    add(
        "sles-16",
        "sles",
        "SUSE Linux Enterprise 16",
        "agama",
        _FW_FIREWALLD,
        registration=True,
        product_id="SLES",
        desktops=_DESKTOPS["sles-16"],
        notes=["Agama profile; AutoYaST is only partially supported on 16."],
    )
    add(
        "leap-16",
        "leap",
        "openSUSE Leap 16",
        "agama",
        _FW_FIREWALLD,
        product_id="Leap_16.0",
        desktops=_DESKTOPS["leap-16"],
        notes=["Agama profile."],
    )
    add(
        "arch",
        "arch",
        "Arch Linux",
        "archinstall",
        _FW_UFW,
        luks=False,
        lvm=False,
        device_required=True,
        mirror=True,
        desktops=_DESKTOPS["arch"],
        notes=[
            "Run the helper from the live ISO; disk device is required.",
            "LUKS and LVM are not offered for the Arch answer file.",
            "UEFI machines only; the whole disk is used.",
        ],
    )
    arch_notes = [
        "Run the helper from the Arch Linux live ISO; disk device is required.",
        "LUKS and LVM are not offered; UEFI machines only, the whole disk is used.",
    ]
    add(
        "cachyos",
        "cachyos",
        "CachyOS",
        "archinstall",
        _FW_UFW,
        luks=False,
        lvm=False,
        device_required=True,
        mirror=True,
        desktops=_DESKTOPS["arch"],
        kernels=["linux-cachyos", "linux-cachyos-lts", "linux"],
        notes=[
            "Installed from the Arch Linux ISO with the CachyOS repository and"
            " kernel; the CachyOS ISO has no unattended mode.",
            "Uses the generic x86-64 repository; the v3/v4 builds need the"
            " CachyOS pacman.",
        ]
        + arch_notes,
    )
    add(
        "endeavouros",
        "endeavouros",
        "EndeavourOS",
        "archinstall",
        _FW_UFW,
        luks=False,
        lvm=False,
        device_required=True,
        mirror=True,
        desktops=_DESKTOPS["endeavouros"],
        notes=[
            "Installed from the Arch Linux ISO with the EndeavourOS repository;"
            " the EndeavourOS ISO has no unattended mode.",
            "Desktops add the EndeavourOS package list of the same name.",
        ]
        + arch_notes,
    )
    add(
        "batocera",
        "batocera",
        "Batocera",
        "batocera",
        "",
        ssh=False,
        firewall=False,
        luks=False,
        lvm=False,
        proxy=False,
        extra_packages=False,
        iso_image=False,
        notes=[
            "Experimental: not tested on hardware.",
            "No installer: flash the image, boot it once, then copy both files"
            " to the SHARE partition.",
            "The agent runs as a Batocera service; no MeshCentral agent.",
        ],
    )
    return out


TARGETS = _targets()
_BY_ID = {t["id"]: t for t in TARGETS}


# ---------------------------------------------------------------------------
# software catalog: (package, label) per section, the package names of each
# catalog's default repositories; third-party repositories are not offered

_DEB_DEV = [
    ("git", "Git"),
    ("build-essential", "Compilers and make"),
    ("cmake", "CMake"),
    ("python3-pip", "Python pip"),
    ("python3-venv", "Python venv"),
    ("golang-go", "Go"),
    ("default-jdk", "Java (OpenJDK)"),
    ("nodejs", "Node.js"),
    ("npm", "npm"),
    ("neovim", "Neovim"),
]
_DEB_MEDIA = [
    ("vlc", "VLC"),
    ("mpv", "mpv"),
    ("ffmpeg", "FFmpeg"),
    ("gimp", "GIMP"),
    ("inkscape", "Inkscape"),
    ("audacity", "Audacity"),
    ("obs-studio", "OBS Studio"),
    ("kdenlive", "Kdenlive"),
    ("handbrake", "HandBrake"),
]
_DEB_REMOTE = [
    ("remmina", "Remmina"),
    ("tigervnc-viewer", "TigerVNC viewer"),
    ("x11vnc", "x11vnc"),
    ("mosh", "Mosh"),
    ("tmux", "tmux"),
    ("rsync", "rsync"),
    ("sshfs", "SSHFS"),
    ("wireguard-tools", "WireGuard tools"),
    ("openvpn", "OpenVPN"),
]
_DEB_SYSTEM = [
    ("htop", "htop"),
    ("btop", "btop"),
    ("ncdu", "ncdu"),
    ("iotop", "iotop"),
    ("smartmontools", "smartmontools"),
    ("lm-sensors", "lm-sensors"),
    ("nvme-cli", "nvme-cli"),
    ("tcpdump", "tcpdump"),
    ("nmap", "Nmap"),
    ("gparted", "GParted"),
    ("fail2ban", "Fail2ban"),
    ("qemu-guest-agent", "QEMU guest agent"),
]
_FEDORA_REMOTE = [
    ("remmina", "Remmina"),
    ("tigervnc", "TigerVNC viewer"),
    ("x11vnc", "x11vnc"),
    ("mosh", "Mosh"),
    ("tmux", "tmux"),
    ("rsync", "rsync"),
    ("fuse-sshfs", "SSHFS"),
    ("wireguard-tools", "WireGuard tools"),
    ("openvpn", "OpenVPN"),
]
_FEDORA_SYSTEM = [
    ("htop", "htop"),
    ("btop", "btop"),
    ("ncdu", "ncdu"),
    ("iotop-c", "iotop"),
    ("smartmontools", "smartmontools"),
    ("lm_sensors", "lm_sensors"),
    ("nvme-cli", "nvme-cli"),
    ("tcpdump", "tcpdump"),
    ("nmap", "Nmap"),
    ("gparted", "GParted"),
    ("fail2ban", "Fail2ban"),
    ("qemu-guest-agent", "QEMU guest agent"),
]
_CATALOG = {
    "debian": {
        "Browsers": [
            ("firefox-esr", "Firefox ESR"),
            ("chromium", "Chromium"),
            ("epiphany-browser", "GNOME Web"),
            ("falkon", "Falkon"),
            ("lynx", "Lynx (text)"),
            ("w3m", "w3m (text)"),
        ],
        "Office": [
            ("libreoffice", "LibreOffice"),
            ("gnumeric", "Gnumeric"),
            ("evince", "Evince (PDF)"),
            ("okular", "Okular (PDF)"),
            ("thunderbird", "Thunderbird"),
            ("calibre", "calibre (e-books)"),
            ("scribus", "Scribus"),
        ],
        "Development": _DEB_DEV,
        "Media": _DEB_MEDIA,
        "Remote tools": _DEB_REMOTE,
        "System tools": _DEB_SYSTEM,
    },
    # Firefox, Chromium and Thunderbird are snap wrappers on Ubuntu
    "ubuntu": {
        "Browsers": [
            ("snap:firefox", "Firefox (snap)"),
            ("snap:chromium", "Chromium (snap)"),
            ("epiphany-browser", "GNOME Web"),
            ("falkon", "Falkon"),
            ("konqueror", "Konqueror"),
            ("lynx", "Lynx (text)"),
            ("w3m", "w3m (text)"),
            ("elinks", "ELinks (text)"),
        ],
        "Office": [
            ("libreoffice", "LibreOffice"),
            ("gnumeric", "Gnumeric"),
            ("evince", "Evince (PDF)"),
            ("okular", "Okular (PDF)"),
            ("calibre", "calibre (e-books)"),
            ("scribus", "Scribus"),
            ("snap:thunderbird", "Thunderbird (snap)"),
        ],
        "Development": _DEB_DEV + [("snap:code", "Code (snap, classic)")],
        "Media": _DEB_MEDIA,
        "Remote tools": _DEB_REMOTE,
        "System tools": _DEB_SYSTEM,
    },
    "fedora": {
        "Browsers": [
            ("firefox", "Firefox"),
            ("chromium", "Chromium"),
            ("epiphany", "GNOME Web"),
            ("falkon", "Falkon"),
            ("lynx", "Lynx (text)"),
            ("w3m", "w3m (text)"),
        ],
        "Office": [
            ("libreoffice", "LibreOffice"),
            ("gnumeric", "Gnumeric"),
            ("evince", "Evince (PDF)"),
            ("okular", "Okular (PDF)"),
            ("thunderbird", "Thunderbird"),
            ("calibre", "calibre (e-books)"),
            ("scribus", "Scribus"),
        ],
        "Development": [
            ("git", "Git"),
            ("gcc", "GCC"),
            ("gcc-c++", "GCC C++"),
            ("make", "make"),
            ("cmake", "CMake"),
            ("python3-pip", "Python pip"),
            ("golang", "Go"),
            ("java-25-openjdk-devel", "Java 25 (OpenJDK)"),
            ("nodejs24", "Node.js 24"),
            ("neovim", "Neovim"),
        ],
        "Media": [
            ("vlc", "VLC"),
            ("mpv", "mpv"),
            ("ffmpeg-free", "FFmpeg (free codecs)"),
            ("gimp", "GIMP"),
            ("inkscape", "Inkscape"),
            ("audacity", "Audacity"),
            ("obs-studio", "OBS Studio"),
            ("kdenlive", "Kdenlive"),
        ],
        "Remote tools": _FEDORA_REMOTE,
        "System tools": _FEDORA_SYSTEM,
    },
    # BaseOS and AppStream of RHEL 9 and 10 and their rebuilds
    "el": {
        "Browsers": [("firefox", "Firefox")],
        "Development": [
            ("git", "Git"),
            ("gcc", "GCC"),
            ("gcc-c++", "GCC C++"),
            ("make", "make"),
            ("cmake", "CMake"),
            ("python3-pip", "Python pip"),
            ("golang", "Go"),
            ("java-21-openjdk-devel", "Java 21 (OpenJDK)"),
            ("nodejs", "Node.js"),
            ("vim-enhanced", "Vim"),
        ],
        "Remote tools": [
            ("cockpit", "Cockpit web console"),
            ("tmux", "tmux"),
            ("rsync", "rsync"),
            ("openssh-clients", "SSH client"),
            ("wireguard-tools", "WireGuard tools"),
        ],
        "System tools": [
            ("smartmontools", "smartmontools"),
            ("lm_sensors", "lm_sensors"),
            ("nvme-cli", "nvme-cli"),
            ("tcpdump", "tcpdump"),
            ("nmap", "Nmap"),
            ("sysstat", "sysstat"),
            ("mtr", "mtr"),
            ("lsof", "lsof"),
            ("qemu-guest-agent", "QEMU guest agent"),
        ],
    },
    "leap": {
        "Browsers": [
            ("MozillaFirefox", "Firefox"),
            ("chromium", "Chromium"),
            ("epiphany", "GNOME Web"),
            ("falkon", "Falkon"),
            ("lynx", "Lynx (text)"),
            ("w3m", "w3m (text)"),
        ],
        "Office": [
            ("libreoffice", "LibreOffice"),
            ("evince", "Evince (PDF)"),
            ("okular", "Okular (PDF)"),
            ("MozillaThunderbird", "Thunderbird"),
            ("scribus", "Scribus"),
        ],
        "Development": [
            ("git", "Git"),
            ("gcc", "GCC"),
            ("gcc-c++", "GCC C++"),
            ("make", "make"),
            ("cmake", "CMake"),
            ("go", "Go"),
            ("java-21-openjdk-devel", "Java 21 (OpenJDK)"),
            ("neovim", "Neovim"),
        ],
        "Media": [
            ("vlc", "VLC"),
            ("mpv", "mpv"),
            ("gimp", "GIMP"),
            ("inkscape", "Inkscape"),
            ("audacity", "Audacity"),
            ("kdenlive", "Kdenlive"),
        ],
        "Remote tools": [
            ("remmina", "Remmina"),
            ("tigervnc", "TigerVNC viewer"),
            ("mosh", "Mosh"),
            ("tmux", "tmux"),
            ("rsync", "rsync"),
            ("sshfs", "SSHFS"),
            ("wireguard-tools", "WireGuard tools"),
            ("openvpn", "OpenVPN"),
        ],
        "System tools": [
            ("htop", "htop"),
            ("btop", "btop"),
            ("ncdu", "ncdu"),
            ("iotop", "iotop"),
            ("smartmontools", "smartmontools"),
            ("sensors", "lm-sensors"),
            ("nvme-cli", "nvme-cli"),
            ("tcpdump", "tcpdump"),
            ("gparted", "GParted"),
            ("fail2ban", "Fail2ban"),
            ("qemu-guest-agent", "QEMU guest agent"),
        ],
    },
    # SLES base modules only
    "sles": {
        "Remote tools": [("tmux", "tmux"), ("rsync", "rsync")],
        "System tools": [
            ("smartmontools", "smartmontools"),
            ("sensors", "lm-sensors"),
            ("nvme-cli", "nvme-cli"),
            ("tcpdump", "tcpdump"),
            ("sysstat", "sysstat"),
            ("lsof", "lsof"),
        ],
    },
    "arch": {
        "Browsers": [
            ("firefox", "Firefox"),
            ("chromium", "Chromium"),
            ("epiphany", "GNOME Web"),
            ("falkon", "Falkon"),
            ("torbrowser-launcher", "Tor Browser launcher"),
            ("lynx", "Lynx (text)"),
            ("w3m", "w3m (text)"),
        ],
        "Office": [
            ("libreoffice-fresh", "LibreOffice"),
            ("gnumeric", "Gnumeric"),
            ("evince", "Evince (PDF)"),
            ("okular", "Okular (PDF)"),
            ("thunderbird", "Thunderbird"),
            ("calibre", "calibre (e-books)"),
            ("scribus", "Scribus"),
        ],
        "Development": [
            ("git", "Git"),
            ("base-devel", "Compilers and make"),
            ("cmake", "CMake"),
            ("python-pip", "Python pip"),
            ("go", "Go"),
            ("jdk-openjdk", "Java (OpenJDK)"),
            ("nodejs", "Node.js"),
            ("npm", "npm"),
            ("neovim", "Neovim"),
            ("code", "Code - OSS"),
        ],
        "Media": [
            ("vlc", "VLC"),
            ("mpv", "mpv"),
            ("ffmpeg", "FFmpeg"),
            ("gimp", "GIMP"),
            ("inkscape", "Inkscape"),
            ("audacity", "Audacity"),
            ("obs-studio", "OBS Studio"),
            ("kdenlive", "Kdenlive"),
            ("handbrake", "HandBrake"),
        ],
        "Gaming": [
            ("steam", "Steam (multilib)"),
            ("wine", "Wine"),
            ("lutris", "Lutris"),
            ("gamemode", "GameMode"),
            ("mangohud", "MangoHud"),
            ("retroarch", "RetroArch"),
            ("dolphin-emu", "Dolphin (GameCube, Wii)"),
            ("prismlauncher", "Prism Launcher"),
        ],
        "Remote tools": [
            ("remmina", "Remmina"),
            ("freerdp", "FreeRDP"),
            ("tigervnc", "TigerVNC"),
            ("x11vnc", "x11vnc"),
            ("mosh", "Mosh"),
            ("tmux", "tmux"),
            ("rsync", "rsync"),
            ("sshfs", "SSHFS"),
            ("wireguard-tools", "WireGuard tools"),
            ("openvpn", "OpenVPN"),
        ],
        "System tools": [
            ("htop", "htop"),
            ("btop", "btop"),
            ("ncdu", "ncdu"),
            ("iotop", "iotop"),
            ("smartmontools", "smartmontools"),
            ("lm_sensors", "lm_sensors"),
            ("nvme-cli", "nvme-cli"),
            ("tcpdump", "tcpdump"),
            ("nmap", "Nmap"),
            ("gparted", "GParted"),
            ("fail2ban", "Fail2ban"),
            ("qemu-guest-agent", "QEMU guest agent"),
        ],
    },
}
# Arch packages in the multilib repository, which the install then enables
_MULTILIB = {"steam"}
_CATALOG_OF = {
    "ubuntu": "ubuntu",
    "debian": "debian",
    "rhel": "el",
    "rocky": "el",
    "alma": "el",
    "fedora": "fedora",
    "leap": "leap",
    "sles": "sles",
    "arch": "arch",
    "cachyos": "arch",
    "endeavouros": "arch",
}
_CATALOG_HELP = {
    "debian": "Installed with the extra packages, from the Debian archive.",
    "ubuntu": "From the Ubuntu archive; Firefox, Chromium, Thunderbird and Code"
    " are installed as snaps.",
    "fedora": "From the Fedora repositories; RPM Fusion packages such as"
    " HandBrake are not offered.",
    "el": "From BaseOS and AppStream only; EPEL packages such as htop are not"
    " offered.",
    "leap": "From the openSUSE repositories; Packman packages such as OBS Studio"
    " are not offered.",
    "sles": "From the SLES base modules only; most apps need SUSE Package Hub,"
    " which is not registered.",
    "arch": "From the Arch repositories, Steam through multilib; AUR packages"
    " are not offered.",
}


# snap: entries (Ubuntu only) go to autoinstall's snaps list, not packages
_SNAP = "snap:"
_CLASSIC_SNAPS = {"code"}


def _catalog(tgt: dict) -> list:
    """The target's catalog as checkgroup choices, in section order."""
    sections = _CATALOG.get(_CATALOG_OF.get(tgt["group"]), {})
    out = []
    for section, entries in sections.items():
        for pkg, label in entries:
            choice = {"value": pkg, "label": label, "section": section}
            if pkg.startswith(_SNAP):
                classic = pkg[len(_SNAP) :] in _CLASSIC_SNAPS
                choice["help"] = "Installed as a snap" + (
                    " with classic confinement" if classic else ""
                )
            out.append(choice)
    return out


# ---------------------------------------------------------------------------
# profile validation

_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,62})?(\.[a-z0-9]([a-z0-9-]{0,62})?)*$"
)
_FW_PORT = re.compile(r"^\d{1,5}/(tcp|udp)$")
_FW_SERVICE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
_USERNAME = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
# written into shell and answer files: no whitespace, quotes or metacharacters
_PROXY = re.compile(r"^https?://[A-Za-z0-9._~%@:/+=-]+$")
# the same, plus pacman's $repo and $arch for Arch mirrors
_MIRROR = re.compile(r"^https?://(?:[A-Za-z0-9._~%@:/+=-]|\$repo|\$arch)+$")
# type, base64 blob, optional comment; no options, no shell metacharacters;
# no ssh-dss, which no target's sshd accepts any more
_SSH_KEY = re.compile(
    r"^(ssh-(?:rsa|ed25519)|ecdsa-sha2-nistp(?:256|384|521)"
    r"|sk-(?:ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com)"
    r" ([A-Za-z0-9+/]+={0,2})( [A-Za-z0-9@._+:=-]+)*$"
)

LOCALES = {
    "en_US.UTF-8": "English (United States)",
    "en_GB.UTF-8": "English (United Kingdom)",
    "de_DE.UTF-8": "German (Germany)",
    "de_AT.UTF-8": "German (Austria)",
    "de_CH.UTF-8": "German (Switzerland)",
    "fr_FR.UTF-8": "French (France)",
    "fr_BE.UTF-8": "French (Belgium)",
    "fr_CH.UTF-8": "French (Switzerland)",
    "it_IT.UTF-8": "Italian",
    "es_ES.UTF-8": "Spanish (Spain)",
    "es_MX.UTF-8": "Spanish (Mexico)",
    "pt_PT.UTF-8": "Portuguese (Portugal)",
    "pt_BR.UTF-8": "Portuguese (Brazil)",
    "nl_NL.UTF-8": "Dutch (Netherlands)",
    "nl_BE.UTF-8": "Dutch (Belgium)",
    "da_DK.UTF-8": "Danish",
    "nb_NO.UTF-8": "Norwegian",
    "sv_SE.UTF-8": "Swedish",
    "fi_FI.UTF-8": "Finnish",
    "pl_PL.UTF-8": "Polish",
    "cs_CZ.UTF-8": "Czech",
    "hu_HU.UTF-8": "Hungarian",
    "ro_RO.UTF-8": "Romanian",
    "tr_TR.UTF-8": "Turkish",
    "ru_RU.UTF-8": "Russian",
    "uk_UA.UTF-8": "Ukrainian",
    "ja_JP.UTF-8": "Japanese",
    "zh_CN.UTF-8": "Chinese (Simplified)",
}

# code: (label, xkb layout, xkb variant, kbd keymap on Arch, YaST alias,
# keymap on SUSE 16); the codes are the SUSE kbd names
KEYBOARDS = {
    "us": ("English (US)", "us", "", "us", "english-us", "us"),
    "gb": ("English (UK)", "gb", "", "uk", "english-uk", "gb"),
    "de": ("German", "de", "", "de-latin1", "german-deadkey", "de"),
    "de-nodeadkeys": (
        "German (no dead keys)",
        "de",
        "nodeadkeys",
        "de-latin1-nodeadkeys",
        "german",
        "de-nodeadkeys",
    ),
    "ch": ("Swiss German", "ch", "", "de_CH-latin1", "german-ch", "ch"),
    "ch-fr": ("Swiss French", "ch", "fr", "fr_CH-latin1", "french-ch", "ch-fr"),
    "fr": ("French", "fr", "", "fr-latin1", "french", "fr"),
    "be": ("Belgian", "be", "", "be-latin1", "belgian", "be"),
    "es": ("Spanish", "es", "", "es", "spanish", "es"),
    "latam": (
        "Spanish (Latin America)",
        "latam",
        "",
        "la-latin1",
        "spanish-lat",
        "latam",
    ),
    "it": ("Italian", "it", "", "it", "italian", "it"),
    "nl": ("Dutch", "nl", "", "nl", "dutch", "nl"),
    "pt": ("Portuguese", "pt", "", "pt-latin1", "portugese", "pt"),
    "br": ("Portuguese (Brazil)", "br", "", "br-abnt2", "portugese-br", "br"),
    "dk": ("Danish", "dk", "", "dk-latin1", "danish", "dk"),
    "no": ("Norwegian", "no", "", "no-latin1", "norwegian", "no"),
    "se": ("Swedish", "se", "", "sv-latin1", "swedish", "se"),
    "fi": ("Finnish", "fi", "", "fi", "finnish", "fi-kotoistus"),
    "pl": ("Polish", "pl", "", "pl", "polish", "pl"),
    "cz": ("Czech", "cz", "", "cz-qwertz", "czech", "cz"),
    "hu": ("Hungarian", "hu", "", "hu", "hungarian", "hu"),
    "tr": ("Turkish", "tr", "", "trq", "turkish", "tr"),
    "jp": ("Japanese", "jp", "", "jp106", "japanese", "jp"),
}

_TZ_REGIONS = (
    "Africa/",
    "America/",
    "Antarctica/",
    "Asia/",
    "Atlantic/",
    "Australia/",
    "Europe/",
    "Indian/",
    "Pacific/",
)


def _timezones() -> list:
    from zoneinfo import available_timezones

    zones = sorted(z for z in available_timezones() if z.startswith(_TZ_REGIONS))
    return ["UTC"] + zones


TIMEZONES = _timezones()


def _one_line(value):
    # every format is line based or hashes one line from stdin
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise serializers.ValidationError("no line breaks or control characters")
    return value


def _key_ok(line: str) -> bool:
    m = _SSH_KEY.match(line)
    if not m:
        return False
    try:
        blob = base64.b64decode(m.group(2), validate=True)
    except ValueError:
        return False
    # the blob starts with its own key type as a length-prefixed string
    size = int.from_bytes(blob[:4], "big")
    return blob[4 : 4 + size] == m.group(1).encode()


class _KeysField(serializers.Field):
    """authorized_keys as text, one key per line (a list is taken too); the
    lines are checked by _SshSerializer, only when the profile uses them."""

    def to_internal_value(self, data):
        if isinstance(data, str):
            lines = data.splitlines()
        elif isinstance(data, list) and all(isinstance(k, str) for k in data):
            lines = data
        else:
            raise serializers.ValidationError("one SSH public key per line")
        return [" ".join(line.split()) for line in lines if line.strip()]

    def to_representation(self, value):
        return "\n".join(value)


class _AdminSerializer(serializers.Serializer):
    name = serializers.RegexField(_USERNAME, required=False)
    password = serializers.CharField(
        required=False, allow_blank=False, validators=[_one_line]
    )
    sudo = serializers.BooleanField(required=False, default=True)


class _SshSerializer(serializers.Serializer):
    enable = serializers.BooleanField(required=False, default=True)
    auth = serializers.ChoiceField(
        ["key", "password", "both"], required=False, default="password"
    )
    authorized_keys = _KeysField(required=False, default="")
    root_login = serializers.BooleanField(required=False, default=False)

    def validate(self, attrs):
        keys = attrs.get("authorized_keys") or []
        # the form hides the keys then, so they are dropped unchecked
        if not attrs.get("enable") or attrs.get("auth") == "password":
            keys = []
        for n, key in enumerate(keys, 1):
            if not _key_ok(key):
                msg = f"line {n} is not an SSH public key: {key[:24]}"
                raise serializers.ValidationError({"authorized_keys": msg})
        attrs["authorized_keys"] = list(dict.fromkeys(keys))
        if attrs.get("enable") and attrs.get("auth") == "key" and not keys:
            raise serializers.ValidationError(
                {"authorized_keys": "Key only needs at least one key"}
            )
        return attrs


class _FirewallSerializer(serializers.Serializer):
    enable = serializers.BooleanField(required=False, default=True)
    allow = serializers.ListField(
        child=serializers.CharField(), required=False, default=list
    )

    def validate_allow(self, value):
        for entry in value:
            if not (_FW_PORT.match(entry) or _FW_SERVICE.match(entry)):
                raise serializers.ValidationError(
                    f"use PORT/tcp, PORT/udp or a service name, not {entry!r}"
                )
        return value


class _DiskSerializer(serializers.Serializer):
    device = serializers.CharField(required=False, allow_blank=True, default="")
    layout = serializers.ChoiceField(["lvm", "direct"], required=False, default="lvm")
    filesystem = serializers.ChoiceField(
        ["ext4", "xfs", "btrfs"], required=False, default="ext4"
    )

    def validate_device(self, value):
        if value and not re.match(r"^/dev/[a-zA-Z0-9/_-]{1,64}$", value):
            raise serializers.ValidationError("not a /dev path")
        return value


class _LuksSerializer(serializers.Serializer):
    enable = serializers.BooleanField(required=False, default=False)
    passphrase = serializers.CharField(
        required=False, allow_blank=False, validators=[_one_line]
    )


class _LinuxProfile(serializers.Serializer):
    hostname = serializers.CharField(default="ulrmm-host")
    locale = serializers.ChoiceField(
        list(LOCALES), required=False, default="en_US.UTF-8"
    )
    keyboard = serializers.ChoiceField(list(KEYBOARDS), required=False, default="us")
    timezone = serializers.ChoiceField(TIMEZONES, required=False, default="UTC")
    desktop = serializers.ChoiceField(
        list(_DESKTOP_LABELS), required=False, default="none"
    )
    kernel = serializers.CharField(required=False, allow_blank=True, default="")
    admin = _AdminSerializer(required=False)
    root_locked = serializers.BooleanField(required=False, default=True)
    ssh = _SshSerializer(required=False)
    firewall = _FirewallSerializer(required=False)
    disk = _DiskSerializer(required=False)
    luks = _LuksSerializer(required=False)
    packages = serializers.ListField(
        child=serializers.RegexField(r"^[a-zA-Z0-9][a-zA-Z0-9.+_-]{0,63}$"),
        required=False,
        default=list,
    )
    packages_catalog = serializers.ListField(
        child=serializers.CharField(), required=False, default=list
    )
    mirror = serializers.CharField(required=False, allow_blank=True, default="")
    proxy = serializers.CharField(required=False, allow_blank=True, default="")
    reg_code = serializers.CharField(required=False, allow_blank=True, default="")

    def validate_hostname(self, value):
        if not _HOSTNAME.match(value):
            raise serializers.ValidationError(
                "lower-case letters, digits and hyphens, dot-separated labels"
            )
        return value


def _section(data: dict, key: str, serializer) -> dict:
    sub = serializer(data=data.get(key) or {})
    sub.is_valid(raise_exception=False)
    if sub.errors:
        raise serializers.ValidationError({key: sub.errors})
    return dict(sub.validated_data)


def profile_defaults(target_id: str) -> dict:
    """The full profile form for the target, without what it does not offer."""
    tgt = _BY_ID[target_id]
    caps = tgt["capabilities"]
    out = serializer_defaults(_LinuxProfile)
    out["disk"]["layout"] = tgt["defaults"]["layout"]
    out["disk"]["filesystem"] = tgt["defaults"]["filesystem"]
    if not caps["luks"]:
        out.pop("luks")
    if not caps["registration"]:
        out.pop("reg_code")
    if not caps["mirror"]:
        out.pop("mirror")
    if tgt["kernels"]:
        out["kernel"] = tgt["kernels"][0]
    else:
        out.pop("kernel")
    if not _catalog(tgt):
        out.pop("packages_catalog")
    if tgt["kind"] == "batocera":
        # what batocera.conf takes; no accounts, disk or packages
        out = {k: out[k] for k in ("hostname", "locale", "keyboard", "timezone")}
    return out


def _choices(pairs) -> list:
    return [{"value": v, "label": label} for v, label in pairs]


def _flat(form: dict, prefix: str = "") -> list:
    out = []
    for key, value in form.items():
        if isinstance(value, dict):
            out += _flat(value, f"{prefix}{key}.")
        else:
            out.append(f"{prefix}{key}")
    return out


_CHOICE_SETS = {
    "linux_locales": _choices((k, f"{v} ({k})") for k, v in LOCALES.items()),
    "linux_keyboards": _choices((k, v[0]) for k, v in KEYBOARDS.items()),
    "linux_timezones": _choices((z, z.replace("_", " ")) for z in TIMEZONES),
}


def choice_sets() -> dict:
    """The long choice lists every target shares; the matrix sends them once
    and the fields name them in choices_ref."""
    return _CHOICE_SETS


_FIELDS = {
    "hostname": {"label": "Host name", "kind": "text"},
    "locale": {"label": "Locale", "kind": "select", "choices_ref": "linux_locales"},
    "keyboard": {
        "label": "Keyboard layout",
        "kind": "select",
        "choices_ref": "linux_keyboards",
    },
    "timezone": {
        "label": "Time zone",
        "kind": "select",
        "choices_ref": "linux_timezones",
    },
    "desktop": {
        "label": "Desktop environment",
        "kind": "select",
        "help": "Installed with its display manager; the machine boots into it.",
    },
    "admin.name": {
        "label": "Admin user",
        "kind": "text",
        "help": "Empty: the site's LAPS account, else ulrmm-admin.",
    },
    "admin.password": {
        "label": "Admin password",
        "kind": "secret",
        "help": "Empty: generated and shown once.",
    },
    "admin.sudo": {"label": "Admin may use sudo", "kind": "bool"},
    "root_locked": {"label": "Lock the root account", "kind": "bool"},
    "ssh.enable": {"label": "SSH server", "kind": "bool"},
    "ssh.auth": {
        "label": "SSH sign-in",
        "kind": "select",
        "choices": _choices(
            (
                ("key", "Key only"),
                ("password", "Password only"),
                ("both", "Key or password"),
            )
        ),
        "show_if": {"ssh.enable": True},
    },
    "ssh.authorized_keys": {
        "label": "Authorized SSH keys",
        "kind": "multiline",
        "help": "One public key per line, for the admin user (and root when"
        " root may sign in).",
        "show_if": {"ssh.enable": True, "ssh.auth": ["key", "both"]},
    },
    "ssh.root_login": {
        "label": "Root may sign in over SSH",
        "kind": "bool",
        "show_if": {"ssh.enable": True},
    },
    "firewall.enable": {"label": "Firewall", "kind": "bool"},
    "firewall.allow": {
        "label": "Allowed ports and services",
        "kind": "list",
        "help": "PORT/tcp, PORT/udp or a service name; SSH is added when on.",
    },
    "disk.device": {"label": "Disk device", "kind": "text"},
    "disk.layout": {"label": "Partition layout", "kind": "select"},
    "disk.filesystem": {"label": "Root file system", "kind": "select"},
    "luks.enable": {"label": "Encrypt the disk (LUKS2)", "kind": "bool"},
    "luks.passphrase": {
        "label": "Disk passphrase",
        "kind": "secret",
        "help": "Empty: generated and shown once.",
        "show_if": {"luks.enable": True},
    },
    "kernel": {
        "label": "Kernel",
        "kind": "select",
        "help": "The CachyOS kernels come from the CachyOS repository; linux is the"
        " Arch kernel.",
    },
    "packages": {
        "label": "Extra packages",
        "kind": "list",
        "group": "software",
        "order": 2,
        "capability": "extra_packages",
    },
    "packages_catalog": {
        "label": "Software catalog",
        "kind": "checkgroup",
        "group": "software",
        "order": 1,
        "capability": "extra_packages",
    },
    "mirror": {"label": "Package mirror URL", "kind": "text"},
    "proxy": {"label": "HTTP proxy URL", "kind": "text"},
    "reg_code": {"label": "Registration code", "kind": "secret"},
}


_ARCH_MIRROR_HELP = (
    "An Arch mirror tried first, as https://host/archlinux/$repo/os/$arch."
)


def profile_fields(target_id: str) -> dict:
    """Labels, kinds and choices for every field of the target's profile
    form, keyed by the dotted path."""
    tgt = _BY_ID[target_id]
    out = {}
    for path in _flat(profile_defaults(target_id)):
        out[path] = dict(_FIELDS[path])
    if tgt["kind"] == "batocera":
        return out
    out["desktop"]["choices"] = _choices(
        (d, _DESKTOP_LABELS[d]) for d in ["none"] + list(tgt["desktops"])
    )
    layouts = ["lvm", "direct"] if tgt["capabilities"]["lvm"] else ["direct"]
    out["disk.layout"]["choices"] = _choices(
        (v, {"lvm": "LVM", "direct": "Plain partitions"}[v]) for v in layouts
    )
    out["disk.filesystem"]["choices"] = _choices((fs, fs) for fs in tgt["filesystems"])
    if tgt["capabilities"]["device_required"]:
        out["disk.device"]["help"] = "Required, for example /dev/sda."
    else:
        out["disk.device"]["help"] = "Empty: the installer chooses."
    if "kernel" in out:
        out["kernel"]["choices"] = _choices((k, _KERNELS[k]) for k in tgt["kernels"])
    if "packages_catalog" in out:
        out["packages_catalog"]["choices"] = _catalog(tgt)
        out["packages_catalog"]["help"] = _CATALOG_HELP[_CATALOG_OF[tgt["group"]]]
    if tgt["kind"] == "archinstall" and "mirror" in out:
        out["mirror"]["help"] = _ARCH_MIRROR_HELP
    return out


def validate_profile(target_id: str, data: dict) -> dict:
    """The cleaned profile, or rest_framework.serializers.ValidationError."""
    tgt = _BY_ID.get(target_id)
    if tgt is None:
        raise serializers.ValidationError({"target": "unknown target"})
    if not isinstance(data, dict):
        raise serializers.ValidationError({"profile": "must be an object"})

    data = prune_blank(data)
    top = _LinuxProfile(data=data)
    if not top.is_valid(raise_exception=False):
        raise serializers.ValidationError(top.errors)
    clean = dict(top.validated_data)
    clean["admin"] = _section(data, "admin", _AdminSerializer)
    clean["ssh"] = _section(data, "ssh", _SshSerializer)
    clean["firewall"] = _section(data, "firewall", _FirewallSerializer)
    clean["disk"] = _section(data, "disk", _DiskSerializer)
    clean["luks"] = _section(data, "luks", _LuksSerializer)
    if tgt["kind"] == "batocera":
        # batocera.conf takes the general fields only
        return clean

    caps = tgt["capabilities"]
    errors = {}
    if clean["luks"].get("enable") and not caps["luks"]:
        errors["luks"] = f"disk encryption is not offered for {tgt['label']}"
    elif (
        clean["luks"].get("enable")
        and clean["disk"]["layout"] == "direct"
        and tgt["kind"] in ("autoinstall", "preseed")
    ):
        # subiquity drops the password for direct, partman's crypto is LVM
        errors["luks"] = f"{tgt['label']} encrypts only the lvm layout"
    disk_errors = {}
    if clean["disk"]["layout"] == "lvm" and not caps["lvm"]:
        disk_errors["layout"] = f"LVM is not offered for {tgt['label']}; use direct"
    fs = clean["disk"]["filesystem"]
    if fs not in tgt["filesystems"]:
        disk_errors["filesystem"] = (
            f"{tgt['label']} installs {' or '.join(tgt['filesystems'])}, not {fs}"
        )
    elif fs == "btrfs" and tgt["kind"] == "kickstart":
        if clean["disk"]["layout"] == "lvm":
            disk_errors["layout"] = (
                "Kickstart puts btrfs on its own volumes; use direct"
            )
    if clean["reg_code"] and not caps["registration"]:
        errors["reg_code"] = f"{tgt['label']} takes no registration code"
    if clean["mirror"] and not caps["mirror"]:
        errors["mirror"] = f"a custom mirror is not offered for {tgt['label']}"
    elif clean["mirror"] and not _MIRROR.match(clean["mirror"]):
        errors["mirror"] = "use http://host/path or https://host/path"
    if clean["proxy"] and not caps["proxy"]:
        errors["proxy"] = f"a proxy is not offered for {tgt['label']}"
    elif clean["proxy"] and not _PROXY.match(clean["proxy"]):
        errors["proxy"] = "use http://host:port or https://host:port"
    if clean["kernel"] and clean["kernel"] not in tgt["kernels"]:
        offered = ", ".join(tgt["kernels"]) or "no kernel choice"
        errors["kernel"] = f"{tgt['label']} offers {offered}"
    offered = {c["value"] for c in _catalog(tgt)}
    unknown = [v for v in clean["packages_catalog"] if v not in offered]
    if unknown:
        errors["packages_catalog"] = (
            f"not in the {tgt['label']} catalog: {', '.join(unknown[:5])}"
        )
    if clean["desktop"] != "none" and clean["desktop"] not in tgt["desktops"]:
        offered = ", ".join(["none"] + list(tgt["desktops"]))
        errors["desktop"] = f"{tgt['label']} offers {offered}"
    if caps["device_required"] and not clean["disk"].get("device"):
        disk_errors["device"] = f"{tgt['label']} needs a disk device"
    if disk_errors:
        errors["disk"] = disk_errors
    if errors:
        raise serializers.ValidationError(errors)
    return clean


# ---------------------------------------------------------------------------
# secrets and first boot

_PW_ALPHABET = string.ascii_letters + string.digits
_SALT_ALPHABET = "./" + string.digits + string.ascii_uppercase + string.ascii_lowercase


def _seed(deployment, purpose: str) -> bytes:
    raw = settings.ENROLL_SIGNING_KEY or ""
    try:
        key = base64.b64decode(raw) if raw else b"\0" * 32
    except Exception:
        key = b"\0" * 32
    return hmac.new(
        key, f"{deployment.uid}:{purpose}".encode(), hashlib.sha256
    ).digest()


def _derived(deployment, purpose: str, length: int = 20) -> str:
    data = _seed(deployment, purpose)
    while len(data) < length:
        data += hashlib.sha256(data).digest()
    return "".join(_PW_ALPHABET[b % len(_PW_ALPHABET)] for b in data[:length])


def _salt(deployment, purpose: str) -> str:
    data = _seed(deployment, purpose + ":salt")
    return "".join(_SALT_ALPHABET[b % 64] for b in data[:16])


def _crypt6(password: str, salt: str) -> str:
    """SHA-512 crypt hash; the password reaches openssl on stdin, never argv."""
    proc = subprocess.run(
        ["openssl", "passwd", "-6", "-salt", salt, "-stdin"],
        input=password + "\n",
        capture_output=True,
        text=True,
        timeout=15,
    )
    out = proc.stdout.strip()
    if proc.returncode != 0 or not out.startswith("$6$"):
        raise RuntimeError("openssl passwd failed")
    return out


def _ident_paths():
    ident = agent_ident()
    nix_bin = ident["identNixBin"]
    svc = ident["identNixSvc"]
    base = svc[: -len(".service")] if svc.endswith(".service") else svc
    name = f"{base}-firstboot"
    directory = f"/usr/local/lib/{nix_bin}-deploy"
    return (
        name,
        directory,
        f"{directory}/firstboot.sh",
        f"/etc/systemd/system/{name}.service",
    )


# the agent package the ISO builder puts on the media; the script turns the
# download script ($1) into a no-op once a package is installed
_SEED = "/var/lib/ulrmm-seed"
_LOCAL_PKG = """#!/bin/bash
try() {
  case $1 in
    *.deb)
      command -v dpkg >/dev/null || return 1
      # a failed postinst would leave the package half configured and
      # break every later apt run; the download script installs instead
      dpkg -i "$1" || { dpkg -r "$(dpkg-deb -f "$1" Package)"; return 1; } ;;
    *.rpm) command -v rpm >/dev/null && rpm -i "$1" ;;
    *.tar.gz)
      t=$(mktemp -d) || return 1
      tar -xzf "$1" -C "$t" && env -u DISPLAY -u XAUTHORITY bash "$t"/*/install.sh
      r=$?
      rm -rf "$t"
      return $r ;;
  esac
}
for dir in /var/lib/ulrmm-seed /cdrom/ulrmm /run/install/repo/ulrmm \\
    /run/install/sources/mount-0000-cdrom/ulrmm /media/cdrom/ulrmm; do
  for pkg in "$dir"/*.deb "$dir"/*.rpm "$dir"/*.tar.gz; do
    if [ -f "$pkg" ] && try "$pkg"; then
      printf ':\\n' > "$1"
      rm -rf /var/lib/ulrmm-seed
      exit 0
    fi
  done
done
exit 1
"""


def _local_path(script_path: str) -> str:
    return script_path.rsplit("/", 1)[0] + "/local.sh"


def _seed_copy(root: str, *sources: str) -> str:
    """Copies the media's ulrmm folder into the installed system (root is its
    mount point); a failure never stops the install."""
    copies = [f"cp -a {src} {root}{_SEED} 2>/dev/null" for src in sources]
    return " || ".join(copies + ["true"])


def _net_wait() -> str:
    """network-online.target fires before the resolver works on a fresh
    Debian install; wait for the server name and a TCP connection to the
    server (at most ten minutes, then carry on anyway; the unit restarts
    on failure)."""
    url = urlparse(signing.api_url())
    host = url.hostname or "localhost"
    port = url.port or 443
    return (
        f"/bin/bash -c 'for i in $(seq 1 120); do getent hosts {host}"
        f' >/dev/null 2>&1 && timeout 5 bash -c "exec 3<>/dev/tcp/{host}/{port}"'
        " 2>/dev/null && exit 0; sleep 5; done'"
    )


def _first_boot_unit(script_path: str, unit_path: str, name: str) -> str:
    return (
        "[Unit]\n"
        f"Description={agent_ident()['identNixBin']} first boot enrollment\n"
        "After=network-online.target systemd-resolved.service"
        " NetworkManager-wait-online.service\n"
        "Wants=network-online.target\n"
        "StartLimitIntervalSec=0\n"
        f"ConditionPathExists={script_path}\n\n"
        "[Service]\n"
        "Type=oneshot\n"
        # Restart=on-failure works for oneshot units since systemd 244
        "Restart=on-failure\n"
        "RestartSec=10s\n"
        f"ExecStartPre=-{_net_wait()}\n"
        # an agent package from the install media replaces the download
        f"ExecStartPre=-/bin/bash {_local_path(script_path)} {script_path}\n"
        # the bootstrap is bash; /bin/sh is dash on Debian and Ubuntu
        f"ExecStart=/bin/bash {script_path}\n"
        f"ExecStartPost=-/bin/systemctl disable {name}.service\n"
        f"ExecStartPost=-/bin/rm -f {unit_path} {script_path}"
        f" {_local_path(script_path)}\n\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode("ascii")


def _inject_cmds(deployment) -> list:
    """Shell commands that write the first-boot unit and script, then enable it.

    base64 bodies carry no shell metacharacters, so no quoting is needed. The
    bootstrap body holds the enrollment token; it is removed by the script and
    the unit once enrollment has run.
    """
    name, directory, script_path, unit_path = _ident_paths()
    body = _b64(_bootstrap(deployment))
    unit = _b64(_first_boot_unit(script_path, unit_path, name))
    local = _local_path(script_path)
    return [
        f"mkdir -p {directory}",
        f"printf %s {body} | base64 -d > {script_path}",
        f"chmod 0700 {script_path}",
        f"printf %s {_b64(_LOCAL_PKG)} | base64 -d > {local}",
        f"chmod 0700 {local}",
        f"printf %s {unit} | base64 -d > {unit_path}",
        f"systemctl enable {name}.service",
    ]


def _sshd_conf(ssh: dict) -> str:
    auth = ssh.get("auth", "password")
    pw = "no" if auth == "key" else "yes"
    key = "no" if auth == "password" else "yes"
    root = "no"
    if ssh.get("root_login"):
        root = "prohibit-password" if auth == "key" else "yes"
    # openssh 8.4 (SLES/Leap 15.5) keeps keyboard-interactive (PAM password
    # prompts) on until ChallengeResponseAuthentication is off; later
    # releases read it as an alias of KbdInteractiveAuthentication
    return (
        f"PasswordAuthentication {pw}\n"
        "KbdInteractiveAuthentication no\n"
        "ChallengeResponseAuthentication no\n"
        f"PubkeyAuthentication {key}\n"
        f"PermitRootLogin {root}\n"
    )


def _keys_cmds(home: str, owner: str, keys: list) -> list:
    body = _b64("".join(k + "\n" for k in keys))
    return [
        f"install -d -m 700 {home}/.ssh",
        f"printf %s {body} | base64 -d > {home}/.ssh/authorized_keys",
        f"chmod 600 {home}/.ssh/authorized_keys",
        f"chown -R {owner}: {home}/.ssh",
        # SELinux labels for files written in the install chroot
        f"restorecon -R {home}/.ssh 2>/dev/null || true",
    ]


def _ssh_cmds(ssh: dict, admin: str, *, native: tuple) -> list:
    """sshd drop-in for the auth choice plus the keys the answer file cannot
    place itself; sshd keeps the first value it reads, so the drop-in sorts
    before the distribution's own."""
    cmds = [
        "install -d -m 755 /etc/ssh/sshd_config.d",
        f"printf %s {_b64(_sshd_conf(ssh))} | base64 -d"
        " > /etc/ssh/sshd_config.d/00-ulrmm.conf",
        "systemctl enable sshd 2>/dev/null || systemctl enable ssh 2>/dev/null || true",
    ]
    keys = ssh.get("authorized_keys") or []
    if keys and "admin" not in native:
        cmds += _keys_cmds(f"/home/{admin}", admin, keys)
    if keys and ssh.get("root_login") and "root" not in native:
        cmds += _keys_cmds("/root", "root", keys)
    return cmds


def _desktop_cmds(tgt: dict, p: dict) -> list:
    if p.get("desktop", "none") == "none":
        return []
    cmds = []
    if tgt["kind"] == "autoinstall":
        # the server installer leaves networkd in charge; the desktop flavours
        # hand every device to NetworkManager like this
        nm = _b64("network:\n  version: 2\n  renderer: NetworkManager\n")
        cmds += [
            "rm -f /etc/netplan/00-installer-config.yaml"
            " /etc/netplan/50-cloud-init.yaml",
            f"printf %s {nm} | base64 -d > /etc/netplan/01-network-manager-all.yaml",
            "chmod 600 /etc/netplan/01-network-manager-all.yaml",
        ]
    cmds.append("systemctl set-default graphical.target")
    return cmds


def _fw_cmds(tool: str, firewall: dict, ssh_enable: bool) -> list:
    entries = list(firewall.get("allow") or [])
    if ssh_enable and not any(e in ("ssh", "22/tcp") for e in entries):
        entries.append("22/tcp")
    if tool == _FW_UFW:
        cmds = [f"ufw allow {e}" for e in entries]
        # Arch enables no service on install
        cmds += ["ufw --force enable", "systemctl enable ufw"]
        return cmds
    cmds = []
    for e in entries:
        flag = "--add-port" if _FW_PORT.match(e) else "--add-service"
        cmds.append(f"firewall-offline-cmd {flag}={e}")
    cmds.append("systemctl enable firewalld")
    return cmds


def _post_cmds(tgt: dict, deployment, p: dict, *, native: tuple = ()) -> list:
    """native: whose authorized_keys the answer file writes itself."""
    cmds = []
    if p["ssh"].get("enable", True):
        if tgt["kind"] == "autoyast":
            # openssh 8.4 on SLES/Leap 15.5 and older reads no drop-ins
            cmds.append(
                "grep -qs '^Include /etc/ssh/sshd_config.d/' /etc/ssh/sshd_config"
                " || sed -i '1i Include /etc/ssh/sshd_config.d/*.conf'"
                " /etc/ssh/sshd_config"
            )
        cmds += _ssh_cmds(p["ssh"], p["_admin_name"], native=native)
    cmds += _desktop_cmds(tgt, p)
    if p["firewall"].get("enable", True):
        cmds += _fw_cmds(tgt["fw_tool"], p["firewall"], p["ssh"].get("enable", True))
    if p.get("root_locked", True):
        cmds.append("passwd -l root 2>/dev/null || true")
    if tgt["kind"] in ("autoyast", "agama") and p["_admin_sudo"]:
        cmds += _suse_sudo_cmds(p["_admin_name"])
    if p.get("proxy"):
        cmds += _proxy_cmds(tgt["kind"], p["proxy"])
    cmds += _inject_cmds(deployment)
    return cmds


def _proxy_cmds(kind: str, proxy: str) -> list:
    """The installed system's package manager goes through the proxy;
    subiquity and debian-installer write it themselves."""
    if kind in ("autoinstall", "preseed"):
        return []
    env = f"printf 'http_proxy=%s\\nhttps_proxy=%s\\n' {proxy} {proxy}"
    cmds = [env + " >> /etc/environment"]
    if kind == "kickstart":
        cmds.append(f"printf 'proxy=%s\\n' {proxy} >> /etc/dnf/dnf.conf")
    elif kind in ("autoyast", "agama"):
        cmds.append(
            "sed -i -e 's|^PROXY_ENABLED=.*|PROXY_ENABLED=\"yes\"|'"
            f" -e 's|^HTTP_PROXY=.*|HTTP_PROXY=\"{proxy}\"|'"
            f" -e 's|^HTTPS_PROXY=.*|HTTPS_PROXY=\"{proxy}\"|' /etc/sysconfig/proxy"
        )
    return cmds


def _suse_sudo_cmds(admin: str) -> list:
    """SUSE's sudoers asks for the target's (root's) password, and root is
    locked, so the admin authenticates with their own password instead."""
    path = "/etc/sudoers.d/50-ulrmm-admin"
    return [
        f"printf '%s\\n' 'Defaults:{admin} !targetpw' '{admin} ALL=(ALL) ALL'"
        f" > {path}",
        f"chmod 0440 {path}",
    ]


# ---------------------------------------------------------------------------
# normalisation (resolve admin, passwords, hashes, the secret list)


def _normalize(tgt: dict, deployment, profile: dict) -> dict:
    p = dict(profile)
    if tgt["kind"] == "batocera":
        # no accounts; the deployment link in the service is the secret
        p.update(_generated={}, _secrets=[str(deployment.uid)])
        return p
    # plaintext the server made up, shown once by the render preview
    generated = {}
    admin = dict(p.get("admin") or {})
    name = admin.get("name") or _laps_account(deployment.site_id) or "ulrmm-admin"
    plain = admin.get("password")
    if not plain:
        plain = generated["admin_password"] = _derived(deployment, "admin")
    p["_admin_name"] = name
    p["_admin_hash"] = _crypt6(plain, _salt(deployment, "admin"))
    p["_admin_sudo"] = admin.get("sudo", True)
    secrets = [p["_admin_hash"]]
    luks = dict(p.get("luks") or {})
    p["_luks_pass"] = ""
    if luks.get("enable") and tgt["capabilities"]["luks"]:
        p["_luks_pass"] = luks.get("passphrase")
        if not p["_luks_pass"]:
            p["_luks_pass"] = _derived(deployment, "luks", 24)
            generated["luks_passphrase"] = p["_luks_pass"]
        secrets.append(p["_luks_pass"])
    p["_generated"] = generated
    if p.get("reg_code"):
        secrets.append(p["reg_code"])
    # the enrollment token is embedded base64 in the first-boot script, not
    # verbatim; it is a short-lived token the public installer link also serves.
    p["_secrets"] = secrets
    return p


# ---------------------------------------------------------------------------
# per-format renderers; each returns a list of file dicts


def _packages(tgt: dict, p: dict, *, ssh_pkg: str) -> list:
    pkgs = ["curl"]
    if p["ssh"].get("enable", True):
        pkgs.append(ssh_pkg)
    if tgt["fw_tool"] == _FW_UFW and tgt["kind"] != "autoinstall":
        pkgs.append("ufw")
    if tgt["fw_tool"] == _FW_FIREWALLD:
        pkgs.append("firewalld")
    if p["_admin_sudo"]:
        pkgs.append("sudo")
    pkgs += [v for v in p.get("packages_catalog") or [] if not v.startswith(_SNAP)]
    pkgs += list(p.get("packages") or [])
    # keep order, drop duplicates
    return list(dict.fromkeys(pkgs))


def _xkb(p: dict) -> tuple:
    _, layout, variant, *_ = KEYBOARDS[p["keyboard"]]
    return layout, variant


def _desktop(tgt: dict, p: dict):
    """What installs the chosen desktop on this target, or None."""
    return tgt["desktops"].get(p.get("desktop", "none"))


def _render_autoinstall(tgt, deployment, p):
    layout, variant = _xkb(p)
    keyboard = {"layout": layout}
    if variant:
        keyboard["variant"] = variant
    packages = _packages(tgt, p, ssh_pkg="openssh-server")
    if _desktop(tgt, p):
        packages.append(_desktop(tgt, p))
    cfg = {
        "version": 1,
        "locale": p["locale"],
        "keyboard": keyboard,
        "timezone": p["timezone"],
        "identity": {
            "realname": p["_admin_name"],
            "username": p["_admin_name"],
            "hostname": p["hostname"],
            "password": p["_admin_hash"],
        },
        "ssh": {
            "install-server": p["ssh"].get("enable", True),
            "authorized-keys": list(p["ssh"].get("authorized_keys") or []),
            "allow-pw": p["ssh"].get("auth") != "key",
        },
        "packages": packages,
        "storage": _autoinstall_storage(p),
    }
    snaps = [
        v[len(_SNAP) :] for v in p.get("packages_catalog") or [] if v.startswith(_SNAP)
    ]
    if snaps:
        cfg["snaps"] = [
            {"name": n, "classic": True} if n in _CLASSIC_SNAPS else {"name": n}
            for n in snaps
        ]
    if p["proxy"]:
        cfg["proxy"] = p["proxy"]
    if p["mirror"]:
        cfg["apt"] = {"primary": [{"arches": ["default"], "uri": p["mirror"]}]}
    cmds = _post_cmds(tgt, deployment, p, native=("admin",))
    cfg["late-commands"] = [_seed_copy("/target", "/cdrom/ulrmm")] + [
        "curtin in-target --target=/target -- sh -c '%s'" % c for c in cmds
    ]
    body = yamlish.dump(cfg)
    if tgt["ubuntu_release"] == "22.04":
        body = "#cloud-config\n" + yamlish.dump({"autoinstall": cfg})
    return [{"name": "autoinstall.yaml", "language": "yaml", "content": body}]


def _autoinstall_storage(p: dict) -> dict:
    layout = {"name": "lvm" if p["disk"]["layout"] == "lvm" else "direct"}
    if p["disk"].get("device"):
        layout["match"] = {"path": p["disk"]["device"]}
    if p["_luks_pass"]:
        layout["password"] = p["_luks_pass"]
    return {"layout": layout}


def _render_preseed(tgt, deployment, p):
    user = p["_admin_name"]
    layout, variant = _xkb(p)
    lines = [
        f"d-i debian-installer/locale string {p['locale']}",
        # the installer takes the variant only from layout(variant) here and
        # writes variantcode back from it
        "d-i keyboard-configuration/xkb-keymap select "
        + (f"{layout}({variant})" if variant else layout),
        "d-i keyboard-configuration/layoutcode string " + layout,
    ]
    if variant:
        lines.append("d-i keyboard-configuration/variantcode string " + variant)
    lines += [
        "d-i netcfg/choose_interface select auto",
        f"d-i netcfg/get_hostname string {p['hostname']}",
        "d-i netcfg/get_domain string local",
    ]
    if p["mirror"]:
        host = re.sub(r"^https?://", "", p["mirror"]).split("/")[0]
        path = "/" + p["mirror"].split(host, 1)[-1].strip("/")
        lines += [
            "d-i mirror/country string manual",
            f"d-i mirror/http/hostname string {host}",
            f"d-i mirror/http/directory string {path}",
        ]
    else:
        lines += [
            "d-i mirror/country string manual",
            "d-i mirror/http/hostname string deb.debian.org",
            "d-i mirror/http/directory string /debian",
        ]
    lines.append(f"d-i mirror/http/proxy string {p['proxy']}")
    lines += [
        "d-i clock-setup/utc boolean true",
        f"d-i time/zone string {p['timezone']}",
        "d-i clock-setup/ntp boolean true",
        "d-i passwd/root-login boolean false",
        "d-i passwd/make-user boolean true",
        f"d-i passwd/user-fullname string {user}",
        f"d-i passwd/username string {user}",
        f"d-i passwd/user-password-crypted password {p['_admin_hash']}",
    ]
    if p["_admin_sudo"]:
        lines.append("d-i passwd/user-default-groups string sudo")
    lines += _preseed_partitioning(p)
    # without this line tasksel installs its default desktop
    tasks = ["standard"]
    if _desktop(tgt, p):
        tasks += ["desktop", _desktop(tgt, p)]
    lines += [
        "d-i apt-setup/no-mirror boolean false",
        f"tasksel tasksel/first multiselect {', '.join(tasks)}",
        f"d-i pkgsel/include string {' '.join(_packages(tgt, p, ssh_pkg='openssh-server'))}",
        "d-i pkgsel/upgrade select none",
        "popularity-contest popularity-contest/participate boolean false",
        "d-i grub-installer/only_debian boolean true",
        "d-i grub-installer/bootdev string default",
        "d-i finish-install/reboot_in_progress note",
    ]
    cmds = _post_cmds(tgt, deployment, p)
    inner = "; ".join(
        [_seed_copy("/target", "/cdrom/ulrmm", "/media/ulrmm")]
        + ['in-target sh -c "%s"' % c for c in cmds]
    )
    lines.append(f"d-i preseed/late_command string {inner}")
    body = "\n".join(lines) + "\n"
    return [{"name": "preseed.cfg", "language": "text", "content": body}]


def _preseed_partitioning(p: dict) -> list:
    method = (
        "crypto"
        if p["_luks_pass"]
        else ("lvm" if p["disk"]["layout"] == "lvm" else "regular")
    )
    lines = []
    if p["disk"].get("device"):
        lines.append(f"d-i partman-auto/disk string {p['disk']['device']}")
    lines += [
        f"d-i partman-auto/method string {method}",
        f"d-i partman/default_filesystem string {p['disk']['filesystem']}",
        "d-i partman-auto/choose_recipe select atomic",
        "d-i partman-lvm/device_remove_lvm boolean true",
        "d-i partman-md/device_remove_md boolean true",
        "d-i partman-lvm/confirm boolean true",
        "d-i partman-lvm/confirm_nooverwrite boolean true",
    ]
    if p["_luks_pass"]:
        lines += [
            "d-i partman-auto-crypto/erase_disks boolean false",
            f"d-i partman-crypto/passphrase password {p['_luks_pass']}",
            f"d-i partman-crypto/passphrase-again password {p['_luks_pass']}",
            "d-i partman-crypto/confirm boolean true",
            "d-i partman-crypto/confirm_nooverwrite boolean true",
        ]
    lines += [
        "d-i partman-partitioning/confirm_write_new_label boolean true",
        "d-i partman/choose_partition select finish",
        "d-i partman/confirm boolean true",
        "d-i partman/confirm_nooverwrite boolean true",
    ]
    return lines


def _ks_layout(p: dict) -> str:
    layout, variant = _xkb(p)
    return shlex.quote(f"{layout} ({variant})") if variant else layout


def _render_kickstart(tgt, deployment, p):
    user = p["_admin_name"]
    ver = tgt["ksver"]
    lines = [
        "text",
        f"lang {p['locale']}",
        "keyboard --xlayouts=" + _ks_layout(p),
        f"timezone {p['timezone']} --utc",
        f"network --bootproto=dhcp --hostname={p['hostname']}",
        "rootpw --lock",
    ]
    groups = "--groups=wheel" if p["_admin_sudo"] else ""
    lines.append(
        f"user --name={user} {groups} --password={p['_admin_hash']} --iscrypted".replace(
            "  ", " "
        )
    )
    fw = "--enabled" if p["firewall"].get("enable", True) else "--disabled"
    ssh_on = p["ssh"].get("enable", True)
    allow = []
    for e in (p["firewall"].get("allow") or []) + (["22/tcp"] if ssh_on else []):
        allow.append(
            f"--port={e.replace('/', ':')}" if _FW_PORT.match(e) else f"--service={e}"
        )
    # @core installs openssh-server anyway, firewalld opens ssh by default
    if not ssh_on and "ssh" not in (p["firewall"].get("allow") or []):
        allow.append("--remove-service=ssh")
    lines.append(f"firewall {fw} " + " ".join(dict.fromkeys(allow)))
    lines.append("selinux --enforcing")
    lines.append("services --enabled=sshd" if ssh_on else "services --disabled=sshd")
    if _desktop(tgt, p):
        # Initial Setup would stop the first graphical boot for questions
        lines += ["xconfig --startxonboot", "firstboot --disable"]
    lines.append("zerombr")
    clear = "clearpart --all --initlabel"
    if p["disk"].get("device"):
        clear += f" --drives={p['disk']['device'].split('/')[-1]}"
    lines.append(clear)
    # without --type Anaconda picks LVM (RHEL) or btrfs (Fedora)
    fs = p["disk"]["filesystem"]
    if fs == "btrfs":
        autopart = "autopart --type=btrfs"
    else:
        kind = "lvm" if p["disk"]["layout"] == "lvm" else "plain"
        autopart = f"autopart --type={kind} --fstype={fs}"
    if p["_luks_pass"]:
        # pykickstart splits the line like a shell, '#' starts a comment
        quoted = shlex.quote(p["_luks_pass"])
        autopart += f" --encrypted --luks-version=luks2 --passphrase={quoted}"
        p["_secrets"].append(quoted)
    lines.append(autopart)
    # an image left in the drive would boot and install again
    lines.append("reboot --eject")
    lines.append("")
    lines.append("%packages")
    lines.append("@^" + (_desktop(tgt, p) or "minimal-environment"))
    for pkg in _packages(tgt, p, ssh_pkg="openssh-server"):
        lines.append(pkg)
    lines.append("%end")
    lines.append("")
    lines.append("%post --nochroot --interpreter=/bin/sh")
    lines.append(
        _seed_copy(
            "/mnt/sysimage",
            "/run/install/repo/ulrmm",
            "/run/install/sources/mount-0000-cdrom/ulrmm",
        )
    )
    lines.append("%end")
    lines.append("")
    lines.append("%post --interpreter=/bin/sh --log=/root/ulrmm-post.log")
    # sshkey takes one key per user, so %post writes authorized_keys
    lines += _post_cmds(tgt, deployment, p)
    lines.append("%end")
    body = "\n".join(lines) + "\n"
    # keep ver reachable for tests/validation
    return [{"name": "ks.cfg", "language": "shell", "content": body, "_ksver": ver}]


def _render_autoyast(tgt, deployment, p):
    root = ET.Element("profile", xmlns="http://www.suse.com/1.0/yast2ns")
    root.set("xmlns:config", "http://www.suse.com/1.0/configns")

    def node(parent, tag, text=None, **attrs):
        el = ET.SubElement(
            parent, tag, {k.replace("_", ":"): v for k, v in attrs.items()}
        )
        if text is not None:
            el.text = text
        return el

    # without confirm=false AutoYaST stops at the summary and asks twice
    mode = node(node(root, "general"), "mode")
    node(mode, "confirm", "false", config_type="boolean")
    lang = node(root, "language")
    node(lang, "language", p["locale"].split(".")[0])
    kb = node(root, "keyboard")
    node(kb, "keymap", KEYBOARDS[p["keyboard"]][4])
    tz = node(root, "timezone")
    node(tz, "hwclock", "UTC")
    node(tz, "timezone", p["timezone"])
    net = node(root, "networking")
    dns = node(net, "dns")
    node(dns, "hostname", p["hostname"])
    node(dns, "dhcp_hostname", "false", config_type="boolean")
    node(net, "keep_install_network", "true", config_type="boolean")
    desktop = _desktop(tgt, p)
    if desktop:
        # NetworkManager instead of wicked, as YaST picks for a desktop
        node(net, "managed", "true", config_type="boolean")

    users = node(root, "users", config_type="list")
    au = node(users, "user")
    node(au, "username", p["_admin_name"])
    node(au, "user_password", p["_admin_hash"])
    node(au, "encrypted", "true", config_type="boolean")
    if p["_admin_sudo"]:
        node(au, "groups", "wheel")
    keys = p["ssh"].get("authorized_keys") or []

    def add_keys(user):
        ak = node(user, "authorized_keys", config_type="list")
        for k in keys:
            node(ak, "listentry", k)

    if keys:
        add_keys(au)
    ru = node(users, "user")
    node(ru, "username", "root")
    node(ru, "user_password", "!")
    node(ru, "encrypted", "true", config_type="boolean")
    if keys and p["ssh"].get("root_login"):
        add_keys(ru)

    sw = node(root, "software")
    pkgs = node(sw, "packages", config_type="list")
    for pkg in _packages(tgt, p, ssh_pkg="openssh"):
        node(pkgs, "package", pkg)
    if desktop:
        node(node(sw, "patterns", config_type="list"), "pattern", desktop)
        node(node(root, "services-manager"), "default_target", "graphical")
    if p["reg_code"]:
        reg = node(root, "suse_register")
        node(reg, "do_registration", "true", config_type="boolean")
        node(reg, "reg_code", p["reg_code"])

    # one partition over the disk; the boot partitions are added by AutoYaST
    part = node(root, "partitioning", config_type="list")
    drive = node(part, "drive")
    node(drive, "use", "all")
    if p["disk"].get("device"):
        node(drive, "device", p["disk"]["device"])
    pt = node(node(drive, "partitions", config_type="list"), "partition")
    node(pt, "size", "max")
    if p["_luks_pass"]:
        node(pt, "crypt_method", "luks2", config_type="symbol")
        node(pt, "crypt_key", p["_luks_pass"])
    if p["disk"]["layout"] == "lvm":
        node(pt, "lvm_group", "system")
        vg = node(part, "drive")
        node(vg, "device", "/dev/system")
        node(vg, "type", "CT_LVM", config_type="symbol")
        pt = node(node(vg, "partitions", config_type="list"), "partition")
        node(pt, "lv_name", "root")
        node(pt, "size", "max")
    node(pt, "mount", "/")
    node(pt, "filesystem", p["disk"]["filesystem"], config_type="symbol")

    scripts = node(root, "scripts")
    chroot = node(scripts, "chroot-scripts", config_type="list")
    sc = node(chroot, "script")
    node(sc, "filename", "ulrmm.sh")
    node(sc, "interpreter", "shell")
    node(sc, "chrooted", "true", config_type="boolean")
    body = (
        "#!/bin/sh\n"
        + "\n".join(_post_cmds(tgt, deployment, p, native=("admin", "root")))
        + "\n"
    )
    src = node(sc, "source")
    src.text = body
    seed = node(chroot, "script")
    node(seed, "filename", "ulrmm-seed.sh")
    node(seed, "interpreter", "shell")
    node(seed, "chrooted", "false", config_type="boolean")
    node(seed, "source", "#!/bin/sh\n" + _seed_copy("/mnt", "/var/adm/mount/ulrmm"))
    xml = '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(
        root, encoding="unicode"
    )
    return [{"name": "autoinst.xml", "language": "xml", "content": xml + "\n"}]


def _render_agama(tgt, deployment, p):
    import json

    profile = {
        "product": {"id": tgt["product_id"]},
        "localization": {
            "language": p["locale"],
            "keyboard": KEYBOARDS[p["keyboard"]][5],
            "timezone": p["timezone"],
        },
        "hostname": {"static": p["hostname"]},
        "user": {
            "fullName": p["_admin_name"],
            "userName": p["_admin_name"],
            "password": p["_admin_hash"],
            "hashedPassword": True,
        },
        "software": {"packages": _packages(tgt, p, ssh_pkg="openssh")},
    }
    if _desktop(tgt, p):
        profile["software"]["patterns"] = [_desktop(tgt, p)]
    if p["reg_code"]:
        profile["product"]["registrationCode"] = p["reg_code"]
    profile["storage"] = _agama_storage(p)
    body = "#!/bin/sh\n" + "\n".join(_post_cmds(tgt, deployment, p)) + "\n"
    profile["scripts"] = {"post": [{"name": "ulrmm", "content": body, "chroot": True}]}
    return [
        {
            "name": "agama-profile.json",
            "language": "json",
            "content": json.dumps(profile, indent=2) + "\n",
        }
    ]


def _agama_storage(p: dict) -> dict:
    """The product's default volumes, with root on the chosen file system;
    volumes given explicitly are not generated again."""
    disk = p["disk"]
    drive = {"search": disk["device"]} if disk["device"] else {}
    drive["partitions"] = [{"search": "*", "delete": True}]
    root = {"filesystem": {"path": "/", "type": disk["filesystem"]}}
    enc = {"luks2": {"password": p["_luks_pass"]}} if p["_luks_pass"] else None
    if disk["layout"] == "lvm":
        drive["alias"] = "system-disk"
        pvs = {"targetDevices": ["system-disk"]}
        if enc:
            pvs["encryption"] = enc
        group = {
            "name": "system",
            "physicalVolumes": [{"generate": pvs}],
            "logicalVolumes": [{"generate": "default"}, root],
        }
        return {"drives": [drive], "volumeGroups": [group]}
    gen = {"generate": "default"}
    if enc:
        gen = {"generate": {"partitions": "default", "encryption": enc}}
        root["encryption"] = enc
    drive["partitions"] += [gen, root]
    return {"drives": [drive]}


def _arch_partition(obj_id, fs_type, mountpoint, start, size, flags) -> dict:
    def mib(value):
        return {
            "value": value,
            "unit": "MiB",
            "sector_size": {"value": 512, "unit": "B"},
        }

    return {
        "obj_id": obj_id,
        "status": "create",
        "type": "primary",
        "start": mib(start),
        "size": mib(size),
        "fs_type": fs_type,
        "mountpoint": mountpoint,
        "mount_options": [],
        "flags": flags,
        "btrfs": [],
        "dev_path": None,
    }


def _render_archinstall(tgt, deployment, p):
    import json

    device = p["disk"]["device"]
    # archinstall creates only the partitions it is given; the helper sets the
    # root size to the rest of the disk on the live system
    partitions = [
        _arch_partition("boot", "fat32", "/boot", 1, 1024, ["boot", "esp"]),
        _arch_partition("root", p["disk"]["filesystem"], "/", 1025, 0, []),
    ]
    cfg = {
        "archinstall-language": "English",
        "hostname": p["hostname"],
        "timezone": p["timezone"],
        "ntp": True,
        "locale_config": {
            "kb_layout": KEYBOARDS[p["keyboard"]][3],
            "sys_enc": "UTF-8",
            "sys_lang": p["locale"].split(".")[0],
        },
        "disk_config": {
            "config_type": "default_layout",
            "device_modifications": [
                {
                    "device": device,
                    "wipe": True,
                    "partitions": partitions,
                }
            ],
        },
        # the live ISO's systemd-networkd DHCP setup, enabled on the target
        "network_config": {"type": "iso"},
        "profile_config": {"profile": {"main": "Minimal", "details": []}},
        "packages": _packages(tgt, p, ssh_pkg="openssh"),
        "services": ["sshd"] if p["ssh"].get("enable", True) else [],
        "custom_commands": _post_cmds(tgt, deployment, p),
        "bootloader_config": {
            "bootloader": "Systemd-boot",
            "uki": False,
            "removable": False,
        },
    }
    repo = _ARCH_REPOS.get(tgt["id"])
    if repo:
        cfg["packages"] = list(dict.fromkeys(repo["packages"] + cfg["packages"]))
        # the install uses one server; the mirror list package has them all
        prefix = repo["server"].split("$")[0]
        cfg["custom_commands"].insert(
            0,
            f"sed -i 's|^Server = {prefix}.*|"
            f"Include = /etc/pacman.d/{repo['mirrorlist']}|' /etc/pacman.conf",
        )
    if tgt["kernels"]:
        cfg["kernels"] = [p.get("kernel") or tgt["kernels"][0]]
    mirrors = {}
    if p.get("mirror"):
        mirrors["custom_servers"] = [{"url": p["mirror"]}]
    if _MULTILIB & set(cfg["packages"]):
        mirrors["optional_repositories"] = ["multilib"]
    if mirrors:
        cfg["mirror_config"] = mirrors
    if _desktop(tgt, p):
        name, greeter = _desktop(tgt, p)[:2]
        if len(_desktop(tgt, p)) > 2:
            cfg["packages"].append("eos-packagelist")
            cfg["custom_commands"].insert(
                1,
                "pacman -S --needed --noconfirm"
                f" $(eos-packagelist {shlex.quote(_desktop(tgt, p)[2])})",
            )
        custom = {}
        if name in ("Sway", "Hyprland"):
            # seat access through logind (polkit) instead of the seatd group
            custom = {"seat_access": "systemd-logind"}
        cfg["profile_config"] = {
            "profile": {
                "main": "Desktop",
                "details": [name],
                "custom_settings": {name: custom},
            },
            "greeter": greeter,
            "gfx_driver": "All open-source",
        }
        # desktops expect NetworkManager and a sound server
        cfg["network_config"] = {"type": "nm"}
        cfg["app_config"] = {"audio_config": {"audio": "pipewire"}}
    creds = {
        "users": [
            {
                "username": p["_admin_name"],
                "enc_password": p["_admin_hash"],
                "sudo": bool(p["_admin_sudo"]),
            }
        ]
    }
    return [
        {
            "name": "user_configuration.json",
            "language": "json",
            "content": json.dumps(cfg, indent=2) + "\n",
        },
        {
            "name": "user_credentials.json",
            "language": "json",
            "content": json.dumps(creds, indent=2) + "\n",
        },
    ]


def _deploy_link(deployment) -> str:
    """The deployment's public installer link for the Linux amd64 archive."""
    from deploy.signing import api_url

    return f"{api_url()}/clients/{deployment.uid}/deploy/?fmt=tgz&arch=amd64"


# a Batocera user service (no .sh, start|stop|status); the first start fetches
# the agent archive from the deployment link and enrolls it. /etc lives in
# RAM, so the agent config is kept in userdata and put back on every start
_BATOCERA_SERVICE = r"""#!/bin/bash
dir=/userdata/system/ulrmm
link='@LINK@'
bin="$dir/@BIN@"
conf='@CONF@'
pidfile=/var/run/ulrmm-agent.pid

running() {
  [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null
}

enroll() {
  t=$(mktemp -d) || return 1
  curl -fsSL --proto =https --retry 10 --retry-delay 15 --retry-all-errors \
    -o "$t/agent.tar.gz" "$link" &&
    tar -xzf "$t/agent.tar.gz" -C "$t" &&
    install -m 0755 "$t/@BIN@-installer/@BIN@" "$bin" &&
    "$bin" -m install -enroll "$t/@BIN@-installer/enroll.jws" &&
    install -m 0600 "$conf" "$dir/agent.conf"
  rc=$?
  rm -rf "$t"
  return $rc
}

start_agent() {
  mkdir -p "$dir" && chmod 700 "$dir" || return 1
  if [ ! -s "$dir/agent.conf" ]; then
    enroll || return 1
  fi
  install -m 0600 "$dir/agent.conf" "$conf" || return 1
  "$bin" -m svc >/dev/null 2>&1 &
  echo $! >"$pidfile"
}

case "$1" in
  start)
    running || start_agent &
    ;;
  stop)
    running && kill "$(cat "$pidfile")"
    rm -f "$pidfile"
    ;;
  status)
    if running; then
      echo running
    else
      echo stopped
      exit 1
    fi
    ;;
esac
"""


def _render_batocera(tgt, deployment, p):
    layout, variant = _xkb(p)
    lines = [
        "# add these lines to system/batocera.conf on the SHARE partition",
        f"system.hostname={p['hostname']}",
        f"system.language={p['locale'].split('.')[0]}",
        f"system.kblayout={layout}",
    ]
    if variant:
        lines.append(f"system.kbvariant={variant}")
    lines += [
        f"system.timezone={p['timezone']}",
        "# a password for the network share instead of open access",
        "system.security.enabled=1",
        "system.services=ulrmm",
    ]
    ident = agent_ident()
    service = (
        _BATOCERA_SERVICE.replace("@LINK@", _deploy_link(deployment))
        .replace("@BIN@", ident["identNixBin"])
        .replace("@CONF@", ident["identNixConf"])
    )
    return [
        {
            "name": "batocera.conf",
            "language": "text",
            "content": "\n".join(lines) + "\n",
        },
        {"name": "ulrmm", "language": "shell", "content": service},
    ]


_RENDERERS = {
    "autoinstall": _render_autoinstall,
    "preseed": _render_preseed,
    "kickstart": _render_kickstart,
    "autoyast": _render_autoyast,
    "agama": _render_agama,
    "archinstall": _render_archinstall,
    "batocera": _render_batocera,
}


def render(target_id: str, deployment, profile: dict):
    """(files, secrets) for one target. files = [{name, language, content}]."""
    tgt = _BY_ID.get(target_id)
    if tgt is None:
        raise serializers.ValidationError({"target": "unknown target"})
    p = _normalize(tgt, deployment, profile)
    files = _RENDERERS[tgt["kind"]](tgt, deployment, p)
    for f in files:
        f.pop("_ksver", None)
    profile["_generated"] = p["_generated"]
    return files, p["_secrets"]


# ---------------------------------------------------------------------------
# bundle extras: ISO inject script, the Arch helper and README.txt

# per target or format: the bundle files the script puts on the ISO and the
# boot argument it adds to the menus; $label is the ISO's volume id
_ISO = {
    "ubuntu-22.04": (
        [("nocloud", "/nocloud")],
        "args='autoinstall \"ds=nocloud;s=/cdrom/nocloud/\"'",
    ),
    "autoinstall": ([("autoinstall.yaml", "/autoinstall.yaml")], "args='autoinstall'"),
    "preseed": (
        [("preseed.cfg", "/preseed.cfg")],
        "args='auto=true priority=critical preseed/file=/cdrom/preseed.cfg'",
    ),
    "kickstart": ([("ks.cfg", "/ks.cfg")], 'args="inst.ks=hd:LABEL=$label:/ks.cfg"'),
    "autoyast": (
        [("autoinst.xml", "/autoinst.xml")],
        'args="autoyast=label://$label/autoinst.xml"',
    ),
    "agama": (
        [("agama-profile.json", "/agama-profile.json")],
        'args="inst.auto=label://$label/agama-profile.json"',
    ),
}

# GRUB and isolinux menus of the supported installer ISOs; missing ones are
# skipped
_ISO_MENUS = (
    "/boot/grub/grub.cfg /boot/grub/loopback.cfg /boot/grub2/grub.cfg"
    " /EFI/BOOT/grub.cfg /isolinux/isolinux.cfg /isolinux/txt.cfg"
    " /isolinux/gtk.cfg /isolinux/spkgtk.cfg /isolinux/spk.cfg"
    " /boot/x86_64/loader/isolinux.cfg"
)

# the argument goes right after the kernel on GRUB linux lines and after
# append on isolinux lines that load an initrd; SUSE's BIOS menu boots the
# hard disk by default, Debian's waits forever or boots its speech entry,
# RHEL's and Fedora's check the media first
_INJECT = r"""#!/bin/sh
# Writes a copy of the installer ISO with the answer file on it and the
# unattended boot argument in its boot menus. Needs xorriso.
# usage: sh inject-iso.sh <installer.iso> <new.iso>
set -eu
[ $# -eq 2 ] || { echo "usage: sh inject-iso.sh <installer.iso> <new.iso>" >&2; exit 2; }
command -v xorriso >/dev/null || { echo "install xorriso first" >&2; exit 1; }
src=$1
dst=$2
[ ! -e "$dst" ] || { echo "$dst exists" >&2; exit 1; }
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
label=$(xorriso -indev "$src" -pvd_info 2>/dev/null | sed -n 's/^Volume Id *: *//p')
[ -n "$label" ] || { echo "$src has no volume id" >&2; exit 1; }
@ARGS@
set --
n=0
for menu in @MENUS@; do
    n=$((n + 1))
    xorriso -osirrox on -indev "$src" -extract "$menu" "$work/$n.in" >/dev/null 2>&1 || continue
    sed -e "s|^\([[:space:]]*linux[a-z0-9]*[[:space:]][[:space:]]*[^[:space:]]*\)|\1 $args|" \
        -e "/initrd=/s|^\([[:space:]]*append\)|\1 $args|" \
        -e 's|^default harddisk$|default linux|' \
        -e 's|^timeout 0$|timeout 50|' -e '/^ontimeout /d' \
        -e ':l' -e 's|[[:space:]][[:space:]]*rd\.live\.check\([[:space:]]\)|\1|' -e 'tl' \
        -e 's|[[:space:]][[:space:]]*rd\.live\.check$||' "$work/$n.in" > "$work/$n.cfg"
    case $menu in *grub*) echo 'set timeout=5' >> "$work/$n.cfg" ;; esac
    set -- "$@" -map "$work/$n.cfg" "$menu"
done
[ $# -gt 0 ] || { echo "no boot menu found in $src" >&2; exit 1; }
xorriso -indev "$src" -outdev "$dst" @MAPS@ "$@" -boot_image any replay
"""

_ARCH_HELPER = r"""#!/bin/sh
# Run from the Arch live ISO in the folder with both JSON files: gives the root
# partition the rest of the disk, then installs without questions.
set -eu
cd "$(dirname "$0")"
python3 - <<'EOF'
import json, os
with open("user_configuration.json") as fh:
    cfg = json.load(fh)
mod = cfg["disk_config"]["device_modifications"][0]
name = os.path.basename(os.path.realpath(mod["device"]))
with open(f"/sys/class/block/{name}/size") as fh:
    mib = int(fh.read()) * 512 // 1048576
root = mod["partitions"][-1]
# one MiB stays free for the backup GPT
root["size"]["value"] = mib - root["start"]["value"] - 1
with open("user_configuration.json", "w") as fh:
    json.dump(cfg, fh, indent=2)
EOF
archinstall --config user_configuration.json --creds user_credentials.json --silent
"""

# the live system trusts the repository's pinned signing keys and lists the
# repository once, so pacstrap installs from it and the target gets it too
_ARCH_REPO_STEP = """systemctl start pacman-init.service
pacman-key --keyserver hkps://keyserver.ubuntu.com --recv-keys @KEYS@
pacman-key --lsign-key @KEYS@
grep -q '^\\[@NAME@\\]' /etc/pacman.conf || printf '%s\\n' @LINES@ >>/etc/pacman.conf
"""


def _arch_helper(target_id: str) -> str:
    repo = _ARCH_REPOS.get(target_id)
    if not repo:
        return _ARCH_HELPER
    lines = ["", f"[{repo['name']}]"]
    if repo["siglevel"]:
        lines.append(f"SigLevel = {repo['siglevel']}")
    lines.append(f"Server = {repo['server']}")
    step = (
        _ARCH_REPO_STEP.replace("@KEYS@", " ".join(repo["keys"]))
        .replace("@NAME@", repo["name"])
        .replace("@LINES@", " ".join(shlex.quote(line) for line in lines))
    )
    run = "archinstall --config"
    return _ARCH_HELPER.replace(run, step + run)


def _inject_script(spec) -> str:
    maps, args = spec
    pairs = " ".join(f'-map "$here/{name}" {path}' for name, path in maps)
    return (
        _INJECT.replace("@ARGS@", args)
        .replace("@MENUS@", _ISO_MENUS)
        .replace("@MAPS@", pairs)
    )


def bundle_extras(target_id: str, files: list):
    """Extra files for the download bundle: inject script or helper, README."""
    tgt = _BY_ID.get(target_id)
    if tgt is None:
        return []
    out = []
    if tgt["kind"] == "archinstall":
        out.append(("run-archinstall.sh", _arch_helper(target_id).encode()))
    elif tgt["kind"] == "batocera":
        pass
    else:
        if target_id == "ubuntu-22.04":
            # 22.04 reads autoinstall only as NoCloud user-data
            body = next(
                (f["content"] for f in files if f["name"] == "autoinstall.yaml"), None
            )
            if body is not None:
                out.append(("nocloud/user-data", body.encode()))
                out.append(("nocloud/meta-data", b""))
        spec = _ISO.get(target_id) or _ISO[tgt["kind"]]
        out.append(("inject-iso.sh", _inject_script(spec).encode()))
    out.append(("README.txt", _readme(target_id, tgt).encode()))
    return out


_ISO_STEPS = (
    "With the installer ISO (needs xorriso; macOS: brew install xorriso):\n"
    "1. sh inject-iso.sh <installer.iso> <new.iso>\n"
    "2. Boot the machine from new.iso (USB stick or virtual drive). The\n"
    "   install runs without questions and erases the target disk.\n\n"
    "Without rebuilding the ISO:\n"
)

_MANUAL = {
    "ubuntu-22.04": (
        "1. Copy the nocloud folder to the root of the installation media.\n"
        '2. Add autoinstall "ds=nocloud;s=/cdrom/nocloud/" to the kernel\n'
        "   command line, before ---.\n"
    ),
    "autoinstall": (
        "1. Copy autoinstall.yaml to the root of the installation media.\n"
        "2. Add autoinstall to the kernel command line, before ---.\n"
    ),
    "preseed": (
        "1. Copy preseed.cfg to the root of the installation media, or host it.\n"
        "2. Boot with: auto=true priority=critical preseed/file=/cdrom/preseed.cfg\n"
        "   (or preseed/url=<url>).\n"
    ),
    "kickstart": (
        "1. Put ks.cfg on a volume labelled OEMDRV (found without boot\n"
        "   arguments), or host it and boot with inst.ks=<url>.\n"
    ),
    "autoyast": (
        "1. Copy autoinst.xml to the root of the installation media and boot\n"
        "   with autoyast=label://<volume id>/autoinst.xml, or host it and use\n"
        "   autoyast=<url>, or autoyast=label://OEMDRV/autoinst.xml.\n"
    ),
    "agama": (
        "1. Host agama-profile.json and boot with inst.auto=<url>, or put it on\n"
        "   a volume labelled OEMDRV and use\n"
        "   inst.auto=label://OEMDRV/agama-profile.json.\n"
        "   Do not add a $schema key on 16.0.\n"
    ),
    "batocera": (
        "Experimental: not tested on hardware.\n\n"
        "1. Write the Batocera image to the disk (decompress the .img.gz) and\n"
        "   boot it once; the first boot creates the SHARE partition.\n"
        "2. On the SHARE partition (network share or the disk):\n"
        "   - add the lines of batocera.conf to system/batocera.conf; when\n"
        "     system.services is set already, add ulrmm to that line,\n"
        "   - copy ulrmm to system/services/ulrmm.\n"
        "3. Reboot, or run batocera-services start ulrmm over SSH. The agent\n"
        "   downloads on its first start while the deployment link is valid.\n"
    ),
    "archinstall": (
        "1. Boot the Arch live ISO on the machine (UEFI).\n"
        "2. Copy this folder onto the live system (USB stick, scp or curl).\n"
        "3. sh run-archinstall.sh\n"
        "   It sizes the root partition to the disk named in\n"
        "   user_configuration.json (everything on it is erased) and runs\n"
        "   archinstall without questions.\n"
    ),
}


def _readme(target_id: str, tgt: dict) -> str:
    kind = tgt["kind"]
    steps = _MANUAL.get(target_id) or _MANUAL[kind]
    if kind not in ("archinstall", "batocera"):
        steps = _ISO_STEPS + steps
    return (
        f"{tgt['label']} unattended install\n\n"
        + steps
        + "\nThe generated files contain install-time secrets. Keep them private.\n"
        "The agent enrolls on first boot once the network is up.\n"
    )
