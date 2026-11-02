# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""
Windows and macOS inventory names -> NVD CPE vendor and product.
Keys are normalise()d names, as the uninstall registry and the macOS
app list report them. Anything not listed counts as unmapped.
"""

import re

_PRODUCTS = {
    # (vendor, product, label): normalised names
    ("google", "chrome", "Google Chrome"): ["google chrome"],
    ("mozilla", "firefox", "Mozilla Firefox"): ["mozilla firefox", "firefox"],
    ("mozilla", "firefox_esr", "Mozilla Firefox ESR"): ["mozilla firefox esr"],
    ("microsoft", "edge_chromium", "Microsoft Edge"): ["microsoft edge"],
    ("7-zip", "7-zip", "7-Zip"): ["7-zip"],
    ("videolan", "vlc_media_player", "VLC media player"): ["vlc media player", "vlc"],
    ("notepad-plus-plus", "notepad\\+\\+", "Notepad++"): ["notepad++"],
    ("adobe", "acrobat_reader_dc", "Adobe Acrobat Reader"): [
        "adobe acrobat reader",
        "adobe acrobat reader dc",
        "adobe acrobat reader dc mui",
        "adobe acrobat",
        "adobe acrobat dc",
    ],
    ("oracle", "jre", "Java"): ["java update", "java"],
    ("oracle", "jdk", "Java SE Development Kit"): ["java se development kit"],
    ("oracle", "openjdk", "OpenJDK"): [
        "openjdk",
        "eclipse temurin jdk with hotspot",
        "eclipse temurin jre with hotspot",
        "microsoft build of openjdk with hotspot",
    ],
    ("zoom", "zoom", "Zoom"): ["zoom", "zoom workplace", "zoom.us"],
    ("teamviewer", "teamviewer", "TeamViewer"): ["teamviewer"],
    ("anydesk", "anydesk", "AnyDesk"): ["anydesk"],
    ("rarlab", "winrar", "WinRAR"): ["winrar"],
    ("putty", "putty", "PuTTY"): ["putty", "putty release"],
    ("openssl", "openssl", "OpenSSL"): ["openssl", "openssl light"],
    ("python", "python", "Python"): ["python"],
    ("nodejs", "node.js", "Node.js"): ["node.js"],
    ("git-scm", "git", "Git"): ["git"],
    ("microsoft", "visual_studio_code", "Visual Studio Code"): [
        "microsoft visual studio code",
        "visual studio code",
    ],
    ("mozilla", "thunderbird", "Mozilla Thunderbird"): [
        "mozilla thunderbird",
        "thunderbird",
    ],
    ("libreoffice", "libreoffice", "LibreOffice"): ["libreoffice"],
    ("filezilla-project", "filezilla_client", "FileZilla"): [
        "filezilla",
        "filezilla client",
    ],
    ("winscp", "winscp", "WinSCP"): ["winscp"],
    ("keepass", "keepass", "KeePass"): ["keepass password safe"],
    ("bitwarden", "bitwarden", "Bitwarden"): ["bitwarden"],
    ("discord", "discord", "Discord"): ["discord"],
    ("valvesoftware", "steam_client", "Steam"): ["steam"],
    ("spotify", "spotify", "Spotify"): ["spotify"],
    ("slack", "slack", "Slack"): ["slack"],
    ("microsoft", "teams", "Microsoft Teams"): [
        "microsoft teams",
        "microsoft teams classic",
    ],
    ("dropbox", "dropbox", "Dropbox"): ["dropbox"],
    ("microsoft", "onedrive", "Microsoft OneDrive"): [
        "microsoft onedrive",
        "onedrive",
    ],
    ("apple", "itunes", "iTunes"): ["itunes"],
    ("wireshark", "wireshark", "Wireshark"): ["wireshark"],
    ("nmap", "nmap", "Nmap"): ["nmap"],
    ("obsproject", "obs_studio", "OBS Studio"): ["obs studio", "obs"],
    ("gimp", "gimp", "GIMP"): ["gimp"],
    ("inkscape", "inkscape", "Inkscape"): ["inkscape"],
    ("audacityteam", "audacity", "Audacity"): ["audacity"],
    ("docker", "desktop", "Docker Desktop"): ["docker desktop", "docker"],
    ("oracle", "vm_virtualbox", "VirtualBox"): ["oracle vm virtualbox", "virtualbox"],
    ("vmware", "workstation", "VMware Workstation"): [
        "vmware workstation",
        "vmware workstation pro",
    ],
    ("postman", "postman", "Postman"): ["postman"],
    ("getpaint", "paint.net", "Paint.NET"): ["paint.net"],
    ("greenshot", "greenshot", "Greenshot"): ["greenshot"],
}

# normalised name -> (vendor, product, label)
CPE_MAP = {name: key for key, names in _PRODUCTS.items() for name in names}

_BRACKETS = re.compile(r"\([^)]*\)|\[[^\]]*\]")
# version and architecture words inside a display name
_NOISE = re.compile(
    r"v?\d+(?:[.+_-]\d+)*[a-z]?|x64|x86|x86_64|amd64|arm64|64-bit|32-bit|-"
)
_VERSION = re.compile(r"\d+(?:\.\d+){0,4}")


def normalise(name: str) -> str:
    name = _BRACKETS.sub(" ", name.lower().replace("®", "").replace("™", ""))
    return " ".join(w for w in name.split() if not _NOISE.fullmatch(w))


def cpe_name(vendor: str, product: str, version: str) -> str:
    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


def match(software) -> tuple[set[tuple[str, str, str]], int]:
    """({(label, version, cpe name)}, how many items have no mapping)."""
    apps, unmapped = set(), 0
    for item in software if isinstance(software, list) else []:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            continue
        hit = CPE_MAP.get(normalise(item["name"]))
        version = _VERSION.match(str(item.get("version") or "").strip())
        if hit and version:
            vendor, product, label = hit
            apps.add((label, version[0], cpe_name(vendor, product, version[0])))
        else:
            unmapped += 1
    return apps, unmapped
