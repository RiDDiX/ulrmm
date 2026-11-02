# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Windows unattended answer files (autounattend.xml) and their first-boot
scripts. The four names matrix.py and the builder views dispatch to:
TARGETS, validate_profile, render, bundle_extras.
"""

import base64
import re
import secrets as _secrets
import xml.etree.ElementTree as ET

from rest_framework import serializers

from ulrmm.agent_ident import agent_ident, agent_task_prefix

from . import signing
from .profile import prune_blank, serializer_defaults

NS = "urn:schemas-microsoft-com:unattend"
WCM = "http://schemas.microsoft.com/WMIConfig/2002/State/"
# the embedded first-boot files; Setup leaves elements of other namespaces alone
XNS = "urn:ulrmm:deploy"

# RunSynchronousCommand/Path holds at most 259 characters, so the specialize
# command only loads the processed answer file and runs the extractor in it
SPECIALIZE_CMD = (
    'powershell.exe -NoProfile -Command "$x=[xml]::new();'
    "$x.Load($env:windir+'\\Panther\\unattend.xml');"
    'iex $x.unattend.Extensions.ExtractScript"'
)
PATH_MAX = 259

# curated IANA -> Windows time zone ids; the default covers anything missing
WIN_TZ = {
    "Etc/UTC": "UTC",
    "UTC": "UTC",
    "Europe/London": "GMT Standard Time",
    "Europe/Berlin": "W. Europe Standard Time",
    "Europe/Paris": "Romance Standard Time",
    "Europe/Madrid": "Romance Standard Time",
    "Europe/Rome": "W. Europe Standard Time",
    "Europe/Amsterdam": "W. Europe Standard Time",
    "Europe/Vienna": "W. Europe Standard Time",
    "Europe/Zurich": "W. Europe Standard Time",
    "Europe/Warsaw": "Central European Standard Time",
    "Europe/Prague": "Central Europe Standard Time",
    "Europe/Athens": "GTB Standard Time",
    "Europe/Helsinki": "FLE Standard Time",
    "Europe/Moscow": "Russian Standard Time",
    "Europe/Istanbul": "Turkey Standard Time",
    "Europe/Lisbon": "GMT Standard Time",
    "Europe/Dublin": "GMT Standard Time",
    "America/New_York": "Eastern Standard Time",
    "America/Chicago": "Central Standard Time",
    "America/Denver": "Mountain Standard Time",
    "America/Phoenix": "US Mountain Standard Time",
    "America/Los_Angeles": "Pacific Standard Time",
    "America/Anchorage": "Alaskan Standard Time",
    "America/Toronto": "Eastern Standard Time",
    "America/Sao_Paulo": "E. South America Standard Time",
    "America/Mexico_City": "Central Standard Time (Mexico)",
    "Asia/Tokyo": "Tokyo Standard Time",
    "Asia/Shanghai": "China Standard Time",
    "Asia/Hong_Kong": "China Standard Time",
    "Asia/Singapore": "Singapore Standard Time",
    "Asia/Kolkata": "India Standard Time",
    "Asia/Dubai": "Arabian Standard Time",
    "Asia/Jerusalem": "Israel Standard Time",
    "Asia/Seoul": "Korea Standard Time",
    "Australia/Sydney": "AUS Eastern Standard Time",
    "Australia/Perth": "W. Australia Standard Time",
    "Pacific/Auckland": "New Zealand Standard Time",
}

# the default local keyboard/layout pair Windows wants in windowsPE
_DEFAULT_LOCALE = "en-US"
_DEFAULT_KEYBOARD = "0409:00000409"
_DEFAULT_TZ = "UTC"

_LANG_NAMES = {
    "ar-SA": "Arabic (Saudi Arabia)",
    "bg-BG": "Bulgarian",
    "cs-CZ": "Czech",
    "da-DK": "Danish",
    "de-AT": "German (Austria)",
    "de-CH": "German (Switzerland)",
    "de-DE": "German (Germany)",
    "el-GR": "Greek",
    "en-AU": "English (Australia)",
    "en-CA": "English (Canada)",
    "en-GB": "English (United Kingdom)",
    "en-IE": "English (Ireland)",
    "en-IN": "English (India)",
    "en-US": "English (United States)",
    "es-ES": "Spanish (Spain)",
    "es-MX": "Spanish (Mexico)",
    "et-EE": "Estonian",
    "fi-FI": "Finnish",
    "fr-BE": "French (Belgium)",
    "fr-CA": "French (Canada)",
    "fr-CH": "French (Switzerland)",
    "fr-FR": "French (France)",
    "he-IL": "Hebrew",
    "hr-HR": "Croatian",
    "hu-HU": "Hungarian",
    "it-IT": "Italian",
    "ja-JP": "Japanese",
    "ko-KR": "Korean",
    "lt-LT": "Lithuanian",
    "lv-LV": "Latvian",
    "nb-NO": "Norwegian (Bokmal)",
    "nl-BE": "Dutch (Belgium)",
    "nl-NL": "Dutch (Netherlands)",
    "pl-PL": "Polish",
    "pt-BR": "Portuguese (Brazil)",
    "pt-PT": "Portuguese (Portugal)",
    "ro-RO": "Romanian",
    "ru-RU": "Russian",
    "sk-SK": "Slovak",
    "sl-SI": "Slovenian",
    "sr-Latn-RS": "Serbian (Latin)",
    "sv-SE": "Swedish",
    "th-TH": "Thai",
    "tr-TR": "Turkish",
    "uk-UA": "Ukrainian",
    "zh-CN": "Chinese (Simplified)",
    "zh-TW": "Chinese (Traditional)",
}
# the languages Windows client media ships in; Server media has fewer
UI_LANGUAGES = [
    code
    for code in _LANG_NAMES
    if code
    not in ("de-AT", "de-CH", "en-AU", "en-CA", "en-IE", "en-IN", "fr-BE", "fr-CH")
    and code != "nl-BE"
]
# format locales are part of every image
LOCALES = [code for code in _LANG_NAMES if code != "sr-Latn-RS"]

# input profiles as in the default input locale table of Windows
KEYBOARDS = {
    "0409:00000409": "English (United States) - US",
    "0409:00020409": "English (United States) - United States-International",
    "0809:00000809": "English (United Kingdom) - United Kingdom",
    "1809:00001809": "English (Ireland) - Irish",
    "4009:00004009": "English (India) - English (India)",
    "0407:00000407": "German (Germany) - German",
    "0C07:00000407": "German (Austria) - German",
    "0807:00000807": "German (Switzerland) - Swiss German",
    "100C:0000100C": "French (Switzerland) - Swiss French",
    "040C:0000040C": "French (France) - French",
    "080C:0000080C": "French (Belgium) - Belgian French",
    "0C0C:00001009": "French (Canada) - Canadian French",
    "0813:00000813": "Dutch (Belgium) - Belgian (Period)",
    "0413:00020409": "Dutch (Netherlands) - United States-International",
    "0410:00000410": "Italian - Italian",
    "0C0A:0000040A": "Spanish (Spain) - Spanish",
    "080A:0000080A": "Spanish (Mexico) - Latin American",
    "0816:00000816": "Portuguese (Portugal) - Portuguese",
    "0416:00000416": "Portuguese (Brazil) - Portuguese (Brazil ABNT)",
    "0415:00000415": "Polish - Polish (Programmers)",
    "0405:00000405": "Czech - Czech",
    "041B:0000041B": "Slovak - Slovak",
    "041D:0000041D": "Swedish - Swedish",
    "0406:00000406": "Danish - Danish",
    "0414:00000414": "Norwegian - Norwegian",
    "040B:0000040B": "Finnish - Finnish",
    "0425:00000425": "Estonian - Estonian",
    "0426:00020426": "Latvian - Latvian (Standard)",
    "0427:00010427": "Lithuanian - Lithuanian",
    "040E:0000040E": "Hungarian - Hungarian",
    "041A:0000041A": "Croatian - Standard",
    "0424:00000424": "Slovenian - Slovenian",
    "0418:00010418": "Romanian - Romanian (Standard)",
    "0402:00030402": "Bulgarian - Bulgarian",
    "0408:00000408": "Greek - Greek",
    "041F:0000041F": "Turkish - Turkish Q",
    "0419:00000419": "Russian - Russian",
    "0422:00020422": "Ukrainian - Ukrainian (Enhanced)",
    "040D:0002040D": "Hebrew - Hebrew (Standard)",
    "0401:00000401": "Arabic - Arabic (101)",
    "0411:{03B5835F-F03C-411B-9CE2-AA23E1171E36}"
    "{A76C93D9-5523-4E90-AAFA-4DB112F9AC76}": "Japanese - Microsoft IME",
    "0412:{A028AE76-01B1-46C2-99C4-ACD9858AE02F}"
    "{B5FE1F02-D5F2-4445-9C03-C568F23C99A1}": "Korean - Microsoft IME",
    "0804:{81D4E9C9-1D3B-41BC-9E6C-4B40BF79E35E}"
    "{FA550B04-5AD7-411F-A5AC-CA038EC515D7}": "Chinese (Simplified) - Microsoft Pinyin",
    "0404:{B115690A-EA02-48D5-A231-E3578D2FDF80}"
    "{B2F9C502-1742-11D4-9790-0080C882687E}": "Chinese (Traditional) - Microsoft Bopomofo",
}

# every Windows time zone id (CLDR windowsZones) with its standard offset
# and a sample city: offset|id|city
_ZONES = """
-12:00|Dateline Standard Time|
-11:00|UTC-11|
-10:00|Aleutian Standard Time|Adak
-10:00|Hawaiian Standard Time|Honolulu
-09:30|Marquesas Standard Time|Marquesas
-09:00|Alaskan Standard Time|Anchorage
-09:00|UTC-09|
-08:00|Pacific Standard Time|Los Angeles
-08:00|Pacific Standard Time (Mexico)|Tijuana
-08:00|UTC-08|
-07:00|Mountain Standard Time|Denver
-07:00|Mountain Standard Time (Mexico)|Mazatlan
-07:00|US Mountain Standard Time|Phoenix
-07:00|Yukon Standard Time|Whitehorse
-06:00|Canada Central Standard Time|Regina
-06:00|Central America Standard Time|Guatemala
-06:00|Central Standard Time|Chicago
-06:00|Central Standard Time (Mexico)|Mexico City
-06:00|Easter Island Standard Time|Easter
-05:00|Cuba Standard Time|Havana
-05:00|Eastern Standard Time|New York
-05:00|Eastern Standard Time (Mexico)|Cancun
-05:00|Haiti Standard Time|Port-au-Prince
-05:00|SA Pacific Standard Time|Bogota
-05:00|Turks And Caicos Standard Time|Grand Turk
-05:00|US Eastern Standard Time|Indianapolis
-04:00|Atlantic Standard Time|Halifax
-04:00|Central Brazilian Standard Time|Cuiaba
-04:00|Pacific SA Standard Time|Santiago
-04:00|SA Western Standard Time|La Paz
-04:00|Venezuela Standard Time|Caracas
-03:30|Newfoundland Standard Time|St Johns
-03:00|Argentina Standard Time|Buenos Aires
-03:00|Bahia Standard Time|Bahia
-03:00|E. South America Standard Time|Sao Paulo
-03:00|Magallanes Standard Time|Punta Arenas
-03:00|Montevideo Standard Time|Montevideo
-03:00|Paraguay Standard Time|Asuncion
-03:00|SA Eastern Standard Time|Cayenne
-03:00|Saint Pierre Standard Time|Miquelon
-03:00|Tocantins Standard Time|Araguaina
-02:00|Greenland Standard Time|Godthab
-02:00|UTC-02|
-01:00|Azores Standard Time|Azores
-01:00|Cape Verde Standard Time|Cape Verde
+00:00|GMT Standard Time|London
+00:00|Greenwich Standard Time|Reykjavik
+00:00|Sao Tome Standard Time|Sao Tome
+00:00|UTC|
+01:00|Central Europe Standard Time|Budapest
+01:00|Central European Standard Time|Warsaw
+01:00|Morocco Standard Time|Casablanca
+01:00|Romance Standard Time|Paris
+01:00|W. Central Africa Standard Time|Lagos
+01:00|W. Europe Standard Time|Berlin
+02:00|E. Europe Standard Time|Chisinau
+02:00|Egypt Standard Time|Cairo
+02:00|FLE Standard Time|Kiev
+02:00|GTB Standard Time|Bucharest
+02:00|Israel Standard Time|Jerusalem
+02:00|Kaliningrad Standard Time|Kaliningrad
+02:00|Libya Standard Time|Tripoli
+02:00|Middle East Standard Time|Beirut
+02:00|Namibia Standard Time|Windhoek
+02:00|South Africa Standard Time|Johannesburg
+02:00|South Sudan Standard Time|Juba
+02:00|Sudan Standard Time|Khartoum
+02:00|West Bank Standard Time|Hebron
+03:00|Arab Standard Time|Riyadh
+03:00|Arabic Standard Time|Baghdad
+03:00|Belarus Standard Time|Minsk
+03:00|E. Africa Standard Time|Nairobi
+03:00|Jordan Standard Time|Amman
+03:00|Russian Standard Time|Moscow
+03:00|Syria Standard Time|Damascus
+03:00|Turkey Standard Time|Istanbul
+03:00|Volgograd Standard Time|Volgograd
+03:30|Iran Standard Time|Tehran
+04:00|Arabian Standard Time|Dubai
+04:00|Astrakhan Standard Time|Astrakhan
+04:00|Azerbaijan Standard Time|Baku
+04:00|Caucasus Standard Time|Yerevan
+04:00|Georgian Standard Time|Tbilisi
+04:00|Mauritius Standard Time|Mauritius
+04:00|Russia Time Zone 3|Samara
+04:00|Saratov Standard Time|Saratov
+04:30|Afghanistan Standard Time|Kabul
+05:00|Central Asia Standard Time|Almaty
+05:00|Ekaterinburg Standard Time|Yekaterinburg
+05:00|Pakistan Standard Time|Karachi
+05:00|Qyzylorda Standard Time|Qyzylorda
+05:00|West Asia Standard Time|Tashkent
+05:30|India Standard Time|Calcutta
+05:30|Sri Lanka Standard Time|Colombo
+05:45|Nepal Standard Time|Katmandu
+06:00|Bangladesh Standard Time|Dhaka
+06:00|Omsk Standard Time|Omsk
+06:30|Myanmar Standard Time|Rangoon
+07:00|Altai Standard Time|Barnaul
+07:00|N. Central Asia Standard Time|Novosibirsk
+07:00|North Asia Standard Time|Krasnoyarsk
+07:00|SE Asia Standard Time|Bangkok
+07:00|Tomsk Standard Time|Tomsk
+07:00|W. Mongolia Standard Time|Hovd
+08:00|China Standard Time|Shanghai
+08:00|North Asia East Standard Time|Irkutsk
+08:00|Singapore Standard Time|Singapore
+08:00|Taipei Standard Time|Taipei
+08:00|Ulaanbaatar Standard Time|Ulaanbaatar
+08:00|W. Australia Standard Time|Perth
+08:45|Aus Central W. Standard Time|Eucla
+09:00|Korea Standard Time|Seoul
+09:00|North Korea Standard Time|Pyongyang
+09:00|Tokyo Standard Time|Tokyo
+09:00|Transbaikal Standard Time|Chita
+09:00|Yakutsk Standard Time|Yakutsk
+09:30|AUS Central Standard Time|Darwin
+09:30|Cen. Australia Standard Time|Adelaide
+10:00|AUS Eastern Standard Time|Sydney
+10:00|E. Australia Standard Time|Brisbane
+10:00|Tasmania Standard Time|Hobart
+10:00|Vladivostok Standard Time|Vladivostok
+10:00|West Pacific Standard Time|Port Moresby
+10:30|Lord Howe Standard Time|Lord Howe
+11:00|Bougainville Standard Time|Bougainville
+11:00|Central Pacific Standard Time|Guadalcanal
+11:00|Magadan Standard Time|Magadan
+11:00|Norfolk Standard Time|Norfolk
+11:00|Russia Time Zone 10|Srednekolymsk
+11:00|Sakhalin Standard Time|Sakhalin
+12:00|Fiji Standard Time|Fiji
+12:00|New Zealand Standard Time|Auckland
+12:00|Russia Time Zone 11|Kamchatka
+12:00|UTC+12|
+12:45|Chatham Islands Standard Time|Chatham
+13:00|Samoa Standard Time|Apia
+13:00|Tonga Standard Time|Tongatapu
+13:00|UTC+13|
+14:00|Line Islands Standard Time|Kiritimati
"""
TIMEZONES = [
    (zone, f"(UTC{off}) {zone}" + (f" ({city})" if city else ""))
    for off, zone, city in (line.split("|") for line in _ZONES.strip().splitlines())
]


def _win_tz(value: str) -> str:
    # a Windows id as given, an IANA name through the curated map
    return WIN_TZ.get(value, value or _DEFAULT_TZ)


# ---------------------------------------------------------------- the matrix


# edition flags: domain join, bitlocker, consumer-features policy, telemetry
# off, unified write filter, a desktop, appx debloat, client-only features
# (Copilot, Recall, widgets). Home honours almost nothing; the serializers
# reject fields a target cannot do.
def _caps(domain, bitlocker, consumer, telemetry, uwf, desktop, appx, client=True):
    return {
        "domain_join": domain,
        "bitlocker": bitlocker,
        "consumer_policy": consumer,
        "telemetry_off": telemetry,
        "uwf": uwf,
        "desktop": desktop,
        "appx_debloat": appx,
        "assistant_recall": client,
        "client_apps": client,
    }


_CLIENT_EDITIONS = {
    # key: (label suffix, image name, caps, extra notes)
    "home": ("Home", "Home", _caps(False, False, False, False, False, True, True), []),
    "pro": ("Pro", "Pro", _caps(True, True, False, False, False, True, True), []),
    "pro-iot": (
        "Pro for IoT",
        "Pro",
        _caps(True, True, False, False, False, True, True),
        ["Pro for IoT installs as Windows Pro; the image name is Pro."],
    ),
    "enterprise": (
        "Enterprise",
        "Enterprise",
        _caps(True, True, True, True, True, True, False),
        [],
    ),
    "iot-enterprise": (
        "IoT Enterprise",
        "IoT Enterprise",
        _caps(True, True, True, True, True, True, False),
        ["IoT Enterprise covers the LTSC image: pick the LTSC release as the version."],
    ),
}


_EOS_10 = (
    "Windows 10 22H2 left support in October 2025; it gets updates only "
    "through Extended Security Updates."
)
_EOS_23H2 = (
    "Windows 11 23H2 Home and Pro left support in November 2025; Enterprise, "
    "Education and IoT Enterprise get updates until November 2026."
)
_LTSC = (
    "LTSC has no Store and few inbox apps. The image name is {image}; check "
    "it with dism /Get-WimInfo on the ISO."
)


def _client_versions(year: str, key: str, img: str) -> dict:
    """value -> {label, image, notes}; the version picks the image name."""
    image = f"Windows {year} {img}"
    if year == "10":
        out = {"22H2": {"label": "22H2", "image": image, "notes": [_EOS_10]}}
        ltsc = ("ltsc2021", "LTSC 2021")
    else:
        out = {
            "23H2": {"label": "23H2", "image": image, "notes": [_EOS_23H2]},
            "24H2": {"label": "24H2", "image": image, "notes": []},
            "25H2": {"label": "25H2", "image": image, "notes": []},
            "26H2": {"label": "26H2", "image": image, "notes": []},
        }
        ltsc = ("ltsc2024", "LTSC 2024")
    if key == "iot-enterprise":
        name = f"Windows {year} IoT Enterprise {ltsc[1]}"
        out[ltsc[0]] = {
            "label": ltsc[1],
            "image": name,
            "notes": [_LTSC.format(image=name)],
        }
    return out


def _client_targets():
    targets = []
    for group, year in (("win10", "10"), ("win11", "11")):
        for key, (suffix, img, caps, notes) in _CLIENT_EDITIONS.items():
            targets.append(
                {
                    "id": f"{group}-{key}",
                    "family": "windows",
                    "group": group,
                    "label": f"Windows {year} {suffix}",
                    "formats": ["autounattend.xml"],
                    "capabilities": dict(caps),
                    "defaults": {
                        "image_name": f"Windows {year} {img}",
                        "image_index": None,
                        "server": False,
                        "telemetry": 1,
                        "version": "22H2" if year == "10" else "26H2",
                    },
                    "versions": _client_versions(year, key, img),
                    "notes": list(notes),
                }
            )
    return targets


def _server_targets():
    targets = []
    for group, year, release in (
        ("server2019", "2019", "1809"),
        ("server2022", "2022", "21H2"),
        ("server2025", "2025", "24H2"),
    ):
        for sku in ("standard", "datacenter"):
            for form in ("core", "desktop"):
                desktop = form == "desktop"
                sku_label = sku.capitalize()
                name = f"Windows Server {year} {sku_label}"
                if desktop:
                    name += " (Desktop Experience)"
                notes = [
                    "Server BitLocker needs the BitLocker feature installed "
                    "first; the first-boot task installs it and reboots.",
                ]
                if not desktop:
                    notes.append(
                        "Server Core has no desktop; the image name usually "
                        "carries no Desktop Experience suffix (verify per ISO)."
                    )
                targets.append(
                    {
                        "id": f"{group}-{sku}-{form}",
                        "family": "windows",
                        "group": group,
                        "label": f"Windows Server {year} {sku_label} "
                        + ("Desktop" if desktop else "Core"),
                        "formats": ["autounattend.xml"],
                        "capabilities": _caps(
                            True, True, False, True, False, desktop, False, False
                        ),
                        "defaults": {
                            "image_name": name,
                            "image_index": None,
                            "server": True,
                            "telemetry": 0,
                            "version": release,
                        },
                        "versions": {
                            release: {
                                "label": f"{year} ({release})",
                                "image": name,
                                "notes": [],
                            }
                        },
                        "notes": notes,
                    }
                )
    return targets


TARGETS = _client_targets() + _server_targets()
_BY_ID = {t["id"]: t for t in TARGETS}


def target(target_id: str):
    return _BY_ID.get(target_id)


# ---------------------------------------------------------------- validation

_HOST_RE = r"^(?!\d+$)[A-Za-z0-9-]{1,15}$"


class _GeneralSerializer(serializers.Serializer):
    hostname = serializers.RegexField(_HOST_RE, required=False, allow_blank=True)
    # per target; validate_profile fills the target's default
    version = serializers.CharField(max_length=16, required=False, allow_blank=True)
    ui_language = serializers.CharField(
        max_length=16, required=False, default=_DEFAULT_LOCALE
    )
    locale = serializers.CharField(
        max_length=16, required=False, default=_DEFAULT_LOCALE
    )
    keyboard = serializers.CharField(
        max_length=96, required=False, default=_DEFAULT_KEYBOARD
    )
    timezone = serializers.CharField(max_length=64, required=False, default=_DEFAULT_TZ)
    image_name = serializers.CharField(max_length=128, required=False, allow_blank=True)
    image_index = serializers.IntegerField(
        required=False, allow_null=True, min_value=1, max_value=50
    )

    def validate_keyboard(self, value):
        return value.upper()

    def validate_timezone(self, value):
        return _win_tz(value)


class _AdminSerializer(serializers.Serializer):
    name = serializers.RegexField(
        r"^[A-Za-z][A-Za-z0-9 _.-]{0,19}$", required=False, allow_blank=True
    )
    password = serializers.CharField(
        max_length=127, required=False, allow_blank=True, trim_whitespace=False
    )


class _DomainSerializer(serializers.Serializer):
    domain = serializers.RegexField(r"^[A-Za-z0-9.-]{1,255}$")
    ou = serializers.CharField(max_length=512, required=False, allow_blank=True)
    username = serializers.CharField(max_length=128)
    password = serializers.CharField(max_length=127, trim_whitespace=False)


class _DiskSerializer(serializers.Serializer):
    wipe = serializers.BooleanField(required=False, default=True)
    disk = serializers.IntegerField(
        required=False, default=0, min_value=0, max_value=16
    )


class _EncryptionSerializer(serializers.Serializer):
    bitlocker = serializers.BooleanField(required=False, default=False)


_FW_RULE = re.compile(r"^(\d{1,5})/(tcp|udp)$")


class _FirewallSerializer(serializers.Serializer):
    on = serializers.BooleanField(required=False, default=True)
    allow = serializers.ListField(
        child=serializers.CharField(max_length=16), required=False, default=list
    )

    def validate_allow(self, value):
        for entry in value:
            m = _FW_RULE.match(entry)
            if not m or not 0 < int(m.group(1)) < 65536:
                raise serializers.ValidationError(
                    f"use PORT/tcp or PORT/udp, not {entry!r}"
                )
        return value


class _RemoteSerializer(serializers.Serializer):
    rdp = serializers.BooleanField(required=False, default=False)
    nla = serializers.BooleanField(required=False, default=True)


_SSH_TYPES = (
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
)
_SSH_AUTH = {
    "key": "Key only",
    "password": "Password only",
    "both": "Key or password",
}


def ssh_keys(text: str) -> list:
    """The non-empty lines of an authorized_keys text."""
    return [line.strip() for line in (text or "").splitlines() if line.strip()]


def _check_ssh_key(line: str) -> bool:
    # type, base64 blob whose first field repeats the type, optional comment
    parts = line.split(None, 2)
    if len(parts) < 2 or parts[0] not in _SSH_TYPES:
        return False
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except ValueError:
        return False
    size = int.from_bytes(blob[:4], "big")
    return len(blob) > 4 + size and blob[4 : 4 + size] == parts[0].encode()


class _SshSerializer(serializers.Serializer):
    enable = serializers.BooleanField(required=False, default=False)
    auth = serializers.CharField(max_length=16, required=False, default="key")
    authorized_keys = serializers.CharField(
        max_length=32768, required=False, allow_blank=True, default=""
    )

    def validate(self, attrs):
        # the keys count only where the form shows them: SSH on, key sign-in
        auth = attrs.get("auth", "key")
        if not attrs.get("enable") or auth not in ("key", "both"):
            return attrs
        keys = ssh_keys(attrs.get("authorized_keys", ""))
        for n, line in enumerate(keys, start=1):
            if not _check_ssh_key(line):
                raise serializers.ValidationError(
                    {
                        "authorized_keys": f"line {n} is not an OpenSSH public key "
                        "(type, key, comment)"
                    }
                )
        # "Key or password" without a key still signs in with the password
        if auth == "key" and not keys:
            raise serializers.ValidationError(
                {"authorized_keys": f"{_SSH_AUTH['key']} needs at least one key"}
            )
        attrs["authorized_keys"] = "\n".join(keys)
        return attrs


_PRIVACY = {
    "default": ("Windows defaults", "Leaves every switch below as Windows ships it."),
    "reduced": (
        "Reduced",
        "Required diagnostic data; no advertising ID, suggestions, feedback "
        "requests or web search.",
    ),
    "maximum": (
        "Maximum",
        "Reduced plus activity history, inking and speech data, error reports, "
        "telemetry services, Copilot and Recall.",
    ),
}
# the form's own choice once a switch differs from the preset
_CUSTOM = "custom"

# privacy switches, on = turned off in Windows: label, help, capability
_SWITCHES = {
    "advertising_id": (
        "Advertising ID off",
        "Apps cannot use the advertising ID for personalised ads.",
        None,
    ),
    "tailored_experiences": (
        "Tailored experiences off",
        "No tips, ads or offers based on the diagnostic data.",
        None,
    ),
    "activity_history": (
        "Activity history off",
        "Windows does not collect, publish or upload the activity history.",
        None,
    ),
    "location": (
        "Location off",
        "Location services off for Windows and apps; the automatic time zone "
        "stops working.",
        None,
    ),
    "copilot": (
        "Copilot off",
        "Turns off the Copilot sidebar up to 23H2 and removes the Copilot app "
        "from 24H2 on.",
        "assistant_recall",
    ),
    "recall": (
        "Recall off",
        "Recall cannot be turned on and saves no snapshots.",
        "assistant_recall",
    ),
    "spotlight": (
        "Spotlight off",
        "No Windows Spotlight pictures, facts or suggestions.",
        "consumer_policy",
    ),
    "consumer_content": (
        "Consumer features off",
        "No automatically installed consumer apps or promoted Store content.",
        "consumer_policy",
    ),
    "web_search": (
        "Web search off",
        "Search in Start and the taskbar shows local results only.",
        None,
    ),
    "widgets": (
        "Widgets off",
        "Removes the widgets board and its news feed.",
        "client_apps",
    ),
    "feedback": (
        "Feedback requests off",
        "Windows does not ask for feedback.",
        None,
    ),
    "onedrive": (
        "OneDrive sync off",
        "The OneDrive client cannot sync files.",
        "client_apps",
    ),
    "edge_telemetry": (
        "Edge diagnostic data off",
        "Microsoft Edge sends no diagnostic data.",
        None,
    ),
    "input_personalization": (
        "Inking and typing data off",
        "No inking and typing data collection or handwriting reports.",
        None,
    ),
    "speech": (
        "Online speech off",
        "Users cannot turn on online speech recognition.",
        None,
    ),
    "settings_suggestions": (
        "Suggestions off",
        "No suggested apps or content in Start, Settings and the lock screen.",
        None,
    ),
    "error_reporting": (
        "Error reporting off",
        "Crash and error reports are not sent to Microsoft.",
        None,
    ),
    "cortana": (
        "Cortana off",
        "Cortana is not allowed.",
        "client_apps",
    ),
    "find_my_device": (
        "Find My Device off",
        "Windows does not report the device location for Find My Device.",
        "client_apps",
    ),
    "tips": (
        "Windows tips off",
        "No tips and tricks notifications.",
        "consumer_policy",
    ),
    "telemetry_tasks": (
        "Telemetry services off",
        "Disables the DiagTrack and push services and the telemetry scheduled "
        "tasks.",
        None,
    ),
    "delivery_optimization": (
        "Peer update sharing off",
        "Updates come from Microsoft only, not from other PCs.",
        None,
    ),
}
# what the presets turn on; switches added later stay out so a stored
# Reduced or Maximum profile renders as before
_REDUCED = (
    "advertising_id",
    "tailored_experiences",
    "web_search",
    "feedback",
    "settings_suggestions",
)
_MAXIMUM = _REDUCED + (
    "activity_history",
    "copilot",
    "recall",
    "spotlight",
    "consumer_content",
    "speech",
    "input_personalization",
    "error_reporting",
    "telemetry_tasks",
    "delivery_optimization",
)
# Recall from 24H2; the Copilot app replaced the sidebar there; Cortana before
_AI_RELEASES = ("24H2", "25H2", "26H2", "ltsc2024")
_ASSISTANT_RELEASES = ("22H2", "23H2", "24H2", "25H2", "26H2")

_PrivacySerializer = type(
    "_PrivacySerializer",
    (serializers.Serializer,),
    {
        "level": serializers.ChoiceField(
            choices=[*_PRIVACY, _CUSTOM], required=False, default="default"
        ),
        **{
            key: serializers.BooleanField(required=False, default=False)
            for key in _SWITCHES
        },
    },
)


def _allowed(caps: dict, key: str) -> bool:
    cap = _SWITCHES[key][2]
    return not cap or bool(caps.get(cap))


def _preset(tgt: dict, level) -> dict:
    """The switches of a preset level on the target; {} for custom."""
    presets = {"default": (), "reduced": _REDUCED, "maximum": _MAXIMUM}
    names = presets.get(level) if isinstance(level, str) else None
    if names is None:
        return {}
    caps = tgt["capabilities"]
    return {key: key in names and _allowed(caps, key) for key in _SWITCHES}


def _presets(tgt: dict) -> dict:
    # what the form fills in when a preset is picked
    given = tgt["defaults"]["telemetry"]
    lowest = 0 if tgt["capabilities"]["telemetry_off"] else 1
    out = {}
    for level, telemetry in (
        ("default", given),
        ("reduced", min(given, 1)),
        ("maximum", lowest),
    ):
        out[level] = {f"privacy.{k}": v for k, v in _preset(tgt, level).items()}
        out[level]["telemetry.level"] = telemetry
    return {"privacy.level": out}


for _tgt in TARGETS:
    _tgt["presets"] = _presets(_tgt)


def privacy_switches(tgt: dict, profile: dict) -> dict:
    """The switches that are on: a profile without them (older links, API
    clients) follows its level, and one the edition lacks stays off."""
    given = profile.get("privacy", {})
    on = _preset(tgt, given.get("level", "default"))
    on.update((key, given[key]) for key in _SWITCHES if key in given)
    if profile.get("debloat", {}).get("consumer_policy"):
        on["consumer_content"] = True
    caps = tgt["capabilities"]
    return {key: bool(on.get(key)) and _allowed(caps, key) for key in _SWITCHES}


class _OobeSerializer(serializers.Serializer):
    skip_privacy_questions = serializers.BooleanField(required=False, default=True)


class _DebloatSerializer(serializers.Serializer):
    appx = serializers.ListField(
        child=serializers.RegexField(r"^[A-Za-z0-9._-]{1,128}$"),
        required=False,
        default=list,
    )


class _TelemetrySerializer(serializers.Serializer):
    level = serializers.IntegerField(
        required=False, default=1, min_value=0, max_value=3
    )


class _UwfSerializer(serializers.Serializer):
    enabled = serializers.BooleanField(required=False, default=False)


# section -> (serializer, capability flag that must be set to use it)
_SECTIONS = {
    "general": (_GeneralSerializer, None),
    "admin": (_AdminSerializer, None),
    "domain": (_DomainSerializer, "domain_join"),
    "disk": (_DiskSerializer, None),
    "encryption": (_EncryptionSerializer, "bitlocker"),
    "firewall": (_FirewallSerializer, None),
    "remote": (_RemoteSerializer, None),
    "ssh": (_SshSerializer, None),
    "debloat": (_DebloatSerializer, None),
    "telemetry": (_TelemetrySerializer, None),
    "privacy": (_PrivacySerializer, None),
    "oobe": (_OobeSerializer, None),
    "uwf": (_UwfSerializer, "uwf"),
}

_NO_DOMAIN = "Enter the domain to join, or clear the join fields."

_EDITION_REASON = {
    "domain_join": "Home editions cannot join a domain.",
    "bitlocker": "This edition does not support BitLocker.",
    "consumer_policy": "The Spotlight, tips and consumer-features policies are "
    "honoured only on Enterprise, Education and IoT Enterprise.",
    "assistant_recall": "Copilot and Recall exist only on Windows client editions.",
    "client_apps": "Server editions have no widgets, Cortana, Find My Device or "
    "OneDrive client.",
    "telemetry_off": "Diagnostic data can be turned off only on Enterprise, "
    "Education and Server; other editions keep at least Required.",
    "uwf": "The Unified Write Filter is available only on Enterprise and "
    "IoT Enterprise.",
}


def _laps_admin(deployment):
    """The admin name LAPS expects for the deployment's site, or the default."""
    from laps.models import LapsPolicy

    policy = LapsPolicy.for_site(deployment.site_id)
    if policy and policy.enabled:
        return policy.account, policy.length
    return "ulrmm-admin", 24


def _gen_password(length: int = 20) -> str:
    # upper, lower, digit and symbol so it passes a complexity policy
    alpha = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz"
    digit = "23456789"
    symbol = "!#%*+-=?"
    length = max(16, min(length, 64))
    pool = alpha + digit + symbol
    out = [
        _secrets.choice(alpha.upper()),
        _secrets.choice(alpha.lower()),
        _secrets.choice(digit),
        _secrets.choice(symbol),
    ]
    out += [_secrets.choice(pool) for _ in range(length - len(out))]
    _secrets.SystemRandom().shuffle(out)
    return "".join(out)


def profile_defaults(target_id: str) -> dict:
    """The full profile form for the target: every section it allows."""
    tgt = target(target_id)
    caps = tgt["capabilities"]
    out = {
        section: serializer_defaults(serializer_cls)
        for section, (serializer_cls, flag) in _SECTIONS.items()
        if not flag or caps.get(flag)
    }
    out["general"]["image_name"] = tgt["defaults"]["image_name"]
    out["general"]["version"] = tgt["defaults"]["version"]
    out["telemetry"]["level"] = tgt["defaults"]["telemetry"]
    return out


def _choices(pairs) -> list:
    return [{"value": value, "label": label} for value, label in pairs]


# the long lists go once into the matrix; fields name them in choices_ref
CHOICE_SETS = {
    "win_ui_languages": _choices((c, _LANG_NAMES[c]) for c in UI_LANGUAGES),
    "win_locales": _choices((c, _LANG_NAMES[c]) for c in LOCALES),
    "win_keyboards": _choices(KEYBOARDS.items()),
    "win_timezones": _choices(TIMEZONES),
}


def choice_sets() -> dict:
    """The shared choice lists of the matrix, by the name fields use."""
    return CHOICE_SETS


def field_choices(meta: dict):
    """The choices of a field, inline or by choices_ref; None without any."""
    if "choices_ref" in meta:
        return CHOICE_SETS[meta["choices_ref"]]
    return meta.get("choices")


def _shown(meta: dict, profile: dict) -> bool:
    # the form's show_if rule: every named path holds the value or one of a list
    for path, want in meta.get("show_if", {}).items():
        section, key = path.split(".")
        have = profile.get(section, {}).get(key)
        if have not in (want if isinstance(want, list) else [want]):
            return False
    return True


_TELEMETRY = {
    0: ("Off (Security)", "Only the data that keeps the security features current."),
    1: ("Required", "The minimum Windows needs to stay secure and up to date."),
    2: ("Enhanced", "Required plus how Windows and apps are used."),
    3: ("Optional", "Required plus browsing, app use and full crash data."),
}


def _help_choices(pairs) -> list:
    return [
        {"value": value, "label": label, "help": help_}
        for value, (label, help_) in pairs
    ]


def profile_fields(target_id: str) -> dict:
    """Labels, help and choices for every field of profile_defaults."""
    tgt = target(target_id)
    caps = tgt["capabilities"]
    levels = [0] if caps.get("telemetry_off") else []
    # Enhanced exists only up to the Windows 10 code base (Server 2022 is
    # build 20348 on it; Server 2025 is on the Windows 11 one)
    old_base = ("win10", "server2019", "server2022")
    levels += [1, 2, 3] if tgt["group"] in old_base else [1, 3]
    versions = tgt["versions"]
    fields = {
        "general.hostname": {
            "label": "Host name",
            "help": "Up to 15 letters, digits and hyphens; empty lets Windows "
            "pick one.",
            "kind": "text",
        },
        "general.version": {
            "label": "Windows release",
            "help": "The release on the install media. It sets the default "
            "image name and the release-specific privacy steps.",
            "kind": "select",
            "choices": _choices((v, d["label"]) for v, d in versions.items()),
        },
        "general.ui_language": {
            "label": "Display language",
            "help": "The ISO must contain this language; most ISOs hold only "
            "the one they were downloaded in.",
            "kind": "select",
            "choices_ref": "win_ui_languages",
        },
        "general.locale": {
            "label": "Region and formats",
            "help": "Date, time, number and currency formats; every image "
            "has all of them.",
            "kind": "select",
            "choices_ref": "win_locales",
        },
        "general.keyboard": {
            "label": "Keyboard",
            "kind": "select",
            "choices_ref": "win_keyboards",
        },
        "general.timezone": {
            "label": "Time zone",
            "kind": "select",
            "choices_ref": "win_timezones",
        },
        "general.image_name": {
            "label": "Image name",
            "help": "The /IMAGE/NAME in install.wim; follows the release unless "
            "changed. dism /Get-WimInfo lists the names on an ISO.",
            "kind": "text",
        },
        "general.image_index": {
            "label": "Image index",
            "help": "Optional; Setup then also matches /IMAGE/INDEX.",
            "kind": "number",
        },
        "admin.name": {
            "label": "Admin account",
            "help": "Defaults to the LAPS account of the site."
            + (
                " Servers use the built-in Administrator."
                if tgt["defaults"]["server"]
                else ""
            ),
            "kind": "text",
        },
        "admin.password": {
            "label": "Admin password",
            "help": "Empty generates one; the preview shows it once.",
            "kind": "secret",
        },
        "domain.domain": {"label": "Domain", "kind": "text"},
        "domain.ou": {"label": "Organizational unit", "kind": "text"},
        "domain.username": {"label": "Join account", "kind": "text"},
        "domain.password": {"label": "Join password", "kind": "secret"},
        "disk.wipe": {
            "label": "Wipe and partition the disk",
            "help": "All data on the disk is lost.",
            "kind": "bool",
        },
        "disk.disk": {"label": "Disk number", "kind": "number"},
        "encryption.bitlocker": {
            "label": "BitLocker",
            "help": "TPM and a recovery password, escrowed after enrollment.",
            "kind": "bool",
        },
        "firewall.on": {"label": "Firewall on", "kind": "bool"},
        "firewall.allow": {
            "label": "Allowed inbound ports",
            "help": "PORT/tcp or PORT/udp, for example 443/tcp.",
            "kind": "list",
        },
        "remote.rdp": {"label": "Remote Desktop", "kind": "bool"},
        "remote.nla": {
            "label": "Network Level Authentication",
            "kind": "bool",
            "show_if": {"remote.rdp": True},
        },
        "ssh.enable": {
            "label": "OpenSSH server",
            "help": "Opens port 22 in the firewall"
            + (
                "."
                if tgt["group"] == "server2025"
                else "; a Feature on Demand from Windows Update, so it needs "
                "internet or a FoD source."
            ),
            "kind": "bool",
        },
        "ssh.auth": {
            "label": "SSH sign-in",
            "help": "Password means the Windows account password.",
            "kind": "select",
            "choices": _choices(_SSH_AUTH.items()),
            "show_if": {"ssh.enable": True},
        },
        "ssh.authorized_keys": {
            "label": "Authorized keys",
            "help": "One OpenSSH public key per line; written to "
            "administrators_authorized_keys for every administrator.",
            "kind": "multiline",
            "show_if": {"ssh.enable": True, "ssh.auth": ["key", "both"]},
        },
        "debloat.appx": {
            "label": "Remove apps",
            "help": "Appx package names, for example Microsoft.XboxApp.",
            "kind": "list",
        },
        "telemetry.level": {
            "label": "Diagnostic data",
            "help": "Privacy Reduced or Maximum lowers this value.",
            "kind": "select",
            "choices": _help_choices((n, _TELEMETRY[n]) for n in levels),
            "group": "privacy",
            "order": 1,
        },
        "privacy.level": {
            "label": "Privacy preset",
            "help": "Fills in the switches below; change any of them for a "
            "custom set.",
            "kind": "select",
            "choices": _help_choices(_PRIVACY.items()),
            "preset": True,
            "group": "privacy",
            "order": 0,
        },
        "oobe.skip_privacy_questions": {
            "label": "Skip OOBE privacy questions",
            "help": "Answers them with everything off; unticked, the user sees "
            "the privacy page at the first sign-in.",
            "kind": "bool",
        },
        "uwf.enabled": {
            "label": "Unified Write Filter",
            "help": "Protects C: after enrollment; the agent's folders and "
            "registry key stay writable.",
            "kind": "bool",
        },
    }
    releases = {
        "recall": [v for v in versions if v in _AI_RELEASES],
        "copilot": [v for v in versions if v in _ASSISTANT_RELEASES],
        "cortana": [v for v in versions if v not in _AI_RELEASES],
    }
    for order, (key, (label, help_, cap)) in enumerate(_SWITCHES.items(), 2):
        meta = {
            "label": label,
            "help": help_,
            "kind": "bool",
            "group": "privacy",
            "order": order,
        }
        if cap:
            meta["capability"] = cap
        if key in releases:
            meta["show_if"] = {"general.version": releases[key]}
        fields[f"privacy.{key}"] = meta
    present = {
        f"{section}.{key}"
        for section, values in profile_defaults(target_id).items()
        for key in values
    }
    return {path: meta for path, meta in fields.items() if path in present}


def _image_name(tgt, general) -> str:
    # a name left at any release's default follows the chosen release
    versions = tgt["versions"]
    version = versions.get(general.get("version") or tgt["defaults"]["version"])
    given = general.get("image_name")
    stock = {d["image"] for d in versions.values()} | {tgt["defaults"]["image_name"]}
    if version and (not given or given in stock):
        return version["image"]
    return given or tgt["defaults"]["image_name"]


def _privacy_notes(tgt, level: str, on: dict) -> list:
    """What the edition cannot do of the privacy level."""
    if not any(on.values()):
        return []
    caps = tgt["capabilities"]
    notes = []
    if level == "maximum" and not caps.get("telemetry_off"):
        notes.append(
            "Diagnostic data stays at Required: Windows honours Off only on "
            "Enterprise, Education, IoT Enterprise and Server. The DiagTrack "
            "service is disabled instead."
        )
    if not caps.get("consumer_policy"):
        notes.append(
            "The consumer-features and Spotlight policies work only on "
            "Enterprise, Education and IoT Enterprise; this edition gets the "
            "suggestion switches of the default user profile, which each user "
            "can turn back on."
        )
    if (level == "maximum" or on["recall"]) and tgt["id"] == "win11-home":
        notes.append(
            "Microsoft documents the Recall policies for Pro and above; Home "
            "gets them written but may ignore them."
        )
    if tgt["id"].endswith("-home"):
        notes.append(
            "Home honours no machine policies; the privacy level is applied "
            "through per-user settings and services instead."
        )
    return notes


def validate_profile(target_id: str, data: dict) -> dict:
    tgt = target(target_id)
    if tgt is None:
        raise serializers.ValidationError({"target": "unknown target"})
    if not isinstance(data, dict):
        raise serializers.ValidationError({"profile": "a profile object is required"})
    caps = tgt["capabilities"]
    errors: dict = {}
    clean: dict = {}
    data = prune_blank(data)
    # the consumer-features switch moved from debloat to privacy; older
    # profiles still send it there
    alias = False
    if isinstance(data.get("debloat"), dict) and "consumer_policy" in data["debloat"]:
        try:
            alias = serializers.BooleanField().run_validation(
                data["debloat"].pop("consumer_policy")
            )
        except serializers.ValidationError as exc:
            errors["debloat"] = {"consumer_policy": exc.detail}

    for section, value in data.items():
        if section not in _SECTIONS:
            errors[section] = "unknown profile section"
            continue
        if section == "domain" and not (value or {}).get("domain"):
            # no domain name: the machine stays in a workgroup, so join
            # details given without one would be dropped unseen
            if any((value or {}).get(k) for k in ("ou", "username", "password")):
                errors[section] = {"domain": [_NO_DOMAIN]}
            continue
        serializer_cls, flag = _SECTIONS[section]
        if flag and not caps.get(flag):
            errors[section] = _EDITION_REASON[flag]
            continue
        if section == "privacy" and isinstance(value, dict):
            # switches not given follow the level
            value = {**_preset(tgt, value.get("level", "default")), **value}
        ser = serializer_cls(data=value if isinstance(value, dict) else {})
        if not ser.is_valid():
            errors[section] = ser.errors
            continue
        clean[section] = dict(ser.validated_data)
        if section == "general" and "ui_language" not in ser.initial_data:
            # one-language media: a profile without a display language keeps
            # the one of its formats, as before the two were split
            if clean[section]["locale"] in UI_LANGUAGES:
                clean[section]["ui_language"] = clean[section]["locale"]

    if alias:
        if not caps.get("consumer_policy"):
            errors.setdefault("debloat", {})["consumer_policy"] = _EDITION_REASON[
                "consumer_policy"
            ]
        elif "privacy" not in errors:
            privacy = clean.setdefault(
                "privacy", serializer_defaults(_PrivacySerializer)
            )
            privacy["consumer_content"] = True
    if "general" in clean and not clean["general"].get("version"):
        clean["general"]["version"] = tgt["defaults"]["version"]
    # every select keeps one of its choices; a field its show_if hides is
    # not checked and goes back to its default; the edition gates the rest
    defaults = profile_defaults(target_id)
    shown_in = {"general": {"version": tgt["defaults"]["version"]}, **clean}
    for path, meta in profile_fields(target_id).items():
        section, key = path.split(".")
        if key not in clean.get(section, {}):
            continue
        if not _shown(meta, shown_in):
            clean[section][key] = defaults[section][key]
            continue
        value = clean[section][key]
        cap = meta.get("capability")
        if cap and value and not caps.get(cap):
            errors.setdefault(section, {})[key] = _EDITION_REASON[cap]
            continue
        if meta.get("preset") and value == _CUSTOM:
            continue
        choices = field_choices(meta)
        if choices is not None and value not in [c["value"] for c in choices]:
            errors.setdefault(section, {})[key] = f"{value!r} is not a choice"
    # telemetry below Required (1) needs a telemetry-off edition
    if (
        "telemetry" in clean
        and clean["telemetry"].get("level", 1) < 1
        and not caps.get("telemetry_off")
    ):
        errors.setdefault("telemetry", {})["level"] = _EDITION_REASON["telemetry_off"]

    if errors:
        raise serializers.ValidationError(errors)
    version = clean.get("general", {}).get("version") or tgt["defaults"]["version"]
    clean["_warnings"] = tgt["versions"][version]["notes"] + _privacy_notes(
        tgt,
        clean.get("privacy", {}).get("level", "default"),
        privacy_switches(tgt, clean),
    )
    return clean


# ------------------------------------------------------------------ render


def _sub(parent, tag, text=None, **attrs):
    el = ET.SubElement(parent, f"{{{NS}}}{tag}")
    for key, val in attrs.items():
        # pass_ -> pass (reserved word), others as given
        el.set(key[:-1] if key.endswith("_") else key, val)
    if text is not None:
        el.text = text
    return el


def _wcm(el, action="add"):
    el.set(f"{{{WCM}}}action", action)
    return el


def _component(settings_el, name, arch="amd64"):
    processor = "amd64" if arch in ("amd64", "arm64") else "x86"
    if arch == "arm64":
        processor = "arm64"
    comp = _sub(settings_el, "component", name=name, processorArchitecture=processor)
    comp.set("publicKeyToken", "31bf3856ad364e35")
    comp.set("language", "neutral")
    comp.set("versionScope", "nonSxS")
    return comp


def _run_sync(parent, order, path, description):
    cmd = _sub(parent, "RunSynchronousCommand")
    _wcm(cmd)
    _sub(cmd, "Order", str(order))
    _sub(cmd, "Path", path)
    _sub(cmd, "Description", description)
    return cmd


def _ident_dir():
    ident = agent_ident()["identWinRegKey"]
    return ident, f"C:\\Windows\\Setup\\Scripts\\{ident}"


def _extract_ps1(ident: str, scripts_dir: str, task: str) -> str:
    # runs from SPECIALIZE_CMD with $x = the processed answer file: lock the
    # directory to SYSTEM and Administrators (SIDs, any language) before any
    # secret lands in it, write the embedded files, put SetupComplete.cmd
    # where Setup runs it, register the start-up task. The task first runs
    # on the next boot; a failed step stops with a non-zero exit.
    return f"""$ErrorActionPreference='Stop'
$dir='{scripts_dir}'
New-Item -Force -ItemType Directory $dir|Out-Null
icacls $dir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F'|Out-Null
if($LASTEXITCODE){{throw "icacls exit $LASTEXITCODE"}}
foreach($f in $x.unattend.Extensions.File){{
  [IO.File]::WriteAllBytes((Join-Path $dir $f.GetAttribute('name')),[Convert]::FromBase64String($f.InnerText))
}}
Move-Item -Force (Join-Path $dir 'SetupComplete.cmd') (Split-Path $dir)
$a=Join-Path $env:SystemDrive 'ulrmm'
if(Test-Path $a){{icacls $a /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F'|Out-Null}}
$xml=Join-Path $dir 'task.xml'
[IO.File]::WriteAllText($xml,@'
{_task_xml(scripts_dir, ident)}
'@,[Text.Encoding]::Unicode)
schtasks /Create /TN '{task}' /XML $xml /F|Out-Null
if($LASTEXITCODE){{throw "schtasks exit $LASTEXITCODE"}}
Remove-Item -Force $xml
"""


def _task_xml(scripts_dir: str, ident: str) -> str:
    # boot trigger as SYSTEM (SID, any language); a laptop on battery must
    # start it too, and the retry loop has no time limit
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
<Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers>
<Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
<Settings>
<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
<StartWhenAvailable>true</StartWhenAvailable>
<Enabled>true</Enabled>
</Settings>
<Actions Context="Author"><Exec><Command>powershell.exe</Command><Arguments>-NoProfile -ExecutionPolicy Bypass -File "{scripts_dir}\\{ident}-bootstrap.ps1"</Arguments></Exec></Actions>
</Task>"""


_CP = "Copilot"
_CP_APP = f"Microsoft.{_CP}"

_POLICIES = "HKLM\\SOFTWARE\\Policies\\Microsoft"
_WIN_POLICIES = _POLICIES + "\\Windows"
_WIN_SOFTWARE = "HKLM\\SOFTWARE\\Microsoft\\Windows"
# Start, lock screen and Spotlight suggestions of a user profile
_CDM_OFF = (
    "ContentDeliveryAllowed",
    "FeatureManagementEnabled",
    "OemPreInstalledAppsEnabled",
    "PreInstalledAppsEnabled",
    "PreInstalledAppsEverEnabled",
    "RotatingLockScreenEnabled",
    "RotatingLockScreenOverlayEnabled",
    "SilentInstalledAppsEnabled",
    "SoftLandingEnabled",
    "SubscribedContent-310093Enabled",
    "SubscribedContent-338387Enabled",
    "SubscribedContent-338388Enabled",
    "SubscribedContent-338389Enabled",
    "SubscribedContent-353694Enabled",
    "SubscribedContent-353696Enabled",
    "SystemPaneSuggestionsEnabled",
)
# the telemetry, CEIP, compatibility appraiser and feedback tasks
_TELEMETRY_TASKS = (
    (
        "\\Microsoft\\Windows\\Application Experience\\",
        "Microsoft Compatibility Appraiser",
    ),
    ("\\Microsoft\\Windows\\Application Experience\\", "ProgramDataUpdater"),
    ("\\Microsoft\\Windows\\Autochk\\", "Proxy"),
    ("\\Microsoft\\Windows\\Customer Experience Improvement Program\\", "Consolidator"),
    (
        "\\Microsoft\\Windows\\Customer Experience Improvement Program\\",
        "KernelCeipTask",
    ),
    ("\\Microsoft\\Windows\\Customer Experience Improvement Program\\", "UsbCeip"),
    (
        "\\Microsoft\\Windows\\DiskDiagnostic\\",
        "Microsoft-Windows-DiskDiagnosticDataCollector",
    ),
    ("\\Microsoft\\Windows\\Feedback\\Siuf\\", "DmClient"),
    ("\\Microsoft\\Windows\\Feedback\\Siuf\\", "DmClientOnScenarioDownload"),
)


def _dw(key: str, name: str, value: int) -> str:
    return f"SetDw '{key}' '{name}' {value}"


def telemetry_level(profile: dict, caps: dict):
    """The one AllowTelemetry value to write, or None to leave it alone."""
    level = profile.get("privacy", {}).get("level", "default")
    given = profile["telemetry"].get("level", 1) if "telemetry" in profile else None
    if level == "maximum":
        return 0 if caps.get("telemetry_off") else 1
    if level == "reduced":
        return min(1 if given is None else given, 1)
    return given


def _privacy_ps1(tgt: dict, profile: dict, ident: str) -> list:
    level = profile.get("privacy", {}).get("level", "default")
    on = privacy_switches(tgt, profile)
    # Home ignores the HKLM policies; the per-user and service switches do
    # the same job there
    home = tgt["id"].endswith("-home")
    version = profile.get("general", {}).get("version") or tgt["defaults"]["version"]
    # (switch, step) in the order they run
    machine = [
        (
            "advertising_id",
            _dw(f"{_WIN_POLICIES}\\AdvertisingInfo", "DisabledByGroupPolicy", 1),
        ),
        (
            "feedback",
            _dw(
                f"{_WIN_POLICIES}\\DataCollection", "DoNotShowFeedbackNotifications", 1
            ),
        ),
        ("web_search", _dw(f"{_WIN_POLICIES}\\Windows Search", "DisableWebSearch", 1)),
        (
            "web_search",
            _dw(f"{_WIN_POLICIES}\\Windows Search", "ConnectedSearchUseWeb", 0),
        ),
    ]
    user = [
        (
            "tailored_experiences",
            "Software\\Policies\\Microsoft\\Windows\\CloudContent|"
            "DisableTailoredExperiencesWithDiagnosticData|1",
        ),
        (
            "web_search",
            "Software\\Policies\\Microsoft\\Windows\\Explorer|"
            "DisableSearchBoxSuggestions|1",
        ),
        (
            "web_search",
            "Software\\Microsoft\\Windows\\CurrentVersion\\Search|BingSearchEnabled|0",
        ),
        (
            "advertising_id",
            "Software\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo|Enabled|0",
        ),
        ("feedback", "Software\\Microsoft\\Siuf\\Rules|NumberOfSIUFInPeriod|0"),
    ]
    user += [
        (
            "settings_suggestions",
            "Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager|"
            f"{name}|0",
        )
        for name in _CDM_OFF
    ]
    if home:
        user += [
            (
                "web_search",
                "Software\\Microsoft\\Windows\\CurrentVersion\\Search|CortanaConsent|0",
            ),
            ("feedback", "Software\\Microsoft\\Siuf\\Rules|PeriodInNanoSeconds|0"),
        ]
    machine += [
        ("activity_history", _dw(f"{_WIN_POLICIES}\\System", "EnableActivityFeed", 0)),
        (
            "activity_history",
            _dw(f"{_WIN_POLICIES}\\System", "PublishUserActivities", 0),
        ),
        (
            "activity_history",
            _dw(f"{_WIN_POLICIES}\\System", "UploadUserActivities", 0),
        ),
        (
            "speech",
            _dw(f"{_POLICIES}\\InputPersonalization", "AllowInputPersonalization", 0),
        ),
        (
            "input_personalization",
            _dw(
                f"{_POLICIES}\\InputPersonalization", "RestrictImplicitInkCollection", 1
            ),
        ),
        (
            "input_personalization",
            _dw(
                f"{_POLICIES}\\InputPersonalization",
                "RestrictImplicitTextCollection",
                1,
            ),
        ),
        (
            "input_personalization",
            _dw(f"{_WIN_POLICIES}\\TextInput", "AllowLinguisticDataCollection", 0),
        ),
        (
            "input_personalization",
            _dw(f"{_WIN_POLICIES}\\TabletPC", "PreventHandwritingDataSharing", 1),
        ),
        (
            "input_personalization",
            _dw(
                f"{_WIN_POLICIES}\\HandwritingErrorReports",
                "PreventHandwritingErrorReports",
                1,
            ),
        ),
        (
            "error_reporting",
            _dw(f"{_WIN_POLICIES}\\Windows Error Reporting", "Disabled", 1),
        ),
        (
            "delivery_optimization",
            _dw(f"{_WIN_POLICIES}\\DeliveryOptimization", "DODownloadMode", 0),
        ),
        (
            "telemetry_tasks",
            "foreach($s in 'DiagTrack','dmwappushservice'){"
            "Stop-Service $s -Force -ErrorAction SilentlyContinue; "
            "Set-Service $s -StartupType Disabled -ErrorAction SilentlyContinue}",
        ),
    ]
    machine += [
        (
            "telemetry_tasks",
            f"Get-ScheduledTask -TaskPath '{path}' -TaskName '{name}' "
            "-ErrorAction SilentlyContinue|Disable-ScheduledTask|Out-Null",
        )
        for path, name in _TELEMETRY_TASKS
    ]
    if home:
        machine += [
            (
                "error_reporting",
                _dw(f"{_WIN_SOFTWARE}\\Windows Error Reporting", "Disabled", 1),
            ),
            (
                "error_reporting",
                "Set-Service WerSvc -StartupType Disabled -ErrorAction SilentlyContinue",
            ),
            (
                "delivery_optimization",
                _dw(
                    f"{_WIN_SOFTWARE}\\CurrentVersion\\DeliveryOptimization\\Config",
                    "DODownloadMode",
                    0,
                ),
            ),
        ]
        user += [
            (
                "input_personalization",
                "Software\\Microsoft\\InputPersonalization|RestrictImplicitInkCollection|1",
            ),
            (
                "input_personalization",
                "Software\\Microsoft\\InputPersonalization|RestrictImplicitTextCollection|1",
            ),
            (
                "input_personalization",
                "Software\\Microsoft\\InputPersonalization\\TrainedDataStore|"
                "HarvestContacts|0",
            ),
            (
                "speech",
                "Software\\Microsoft\\Personalization\\Settings|AcceptedPrivacyPolicy|0",
            ),
            ("input_personalization", "Software\\Microsoft\\Input\\TIPC|Enabled|0"),
            # the Settings switch behind the tailored-experiences policy
            (
                "tailored_experiences",
                "Software\\Microsoft\\Windows\\CurrentVersion\\Privacy|"
                "TailoredExperiencesWithDiagnosticDataEnabled|0",
            ),
            (
                "delivery_optimization",
                "Software\\Microsoft\\Windows\\CurrentVersion\\DeliveryOptimization\\"
                "Settings|DownloadMode|0",
            ),
        ]
    user.append(
        (
            "spotlight",
            "Software\\Policies\\Microsoft\\Windows\\CloudContent|"
            "DisableWindowsSpotlightFeatures|1",
        )
    )
    if version in _AI_RELEASES:
        # Recall: not offered, and no snapshots
        machine += [
            ("recall", _dw(f"{_WIN_POLICIES}\\WindowsAI", "AllowRecallEnablement", 0)),
            ("recall", _dw(f"{_WIN_POLICIES}\\WindowsAI", "DisableAIDataAnalysis", 1)),
        ]
    if version in ("22H2", "23H2"):
        # the sidebar of these releases follows a user policy; from 24H2
        # it is an app the debloat step removes
        user.append(
            (
                "copilot",
                f"Software\\Policies\\Microsoft\\Windows\\Windows{_CP}|"
                f"TurnOffWindows{_CP}|1",
            )
        )
    machine += [
        (
            "location",
            _dw(f"{_WIN_POLICIES}\\AppPrivacy", "LetAppsAccessLocation", 2),
        ),
        ("location", _dw(f"{_WIN_POLICIES}\\LocationAndSensors", "DisableLocation", 1)),
        ("widgets", _dw(f"{_POLICIES}\\Dsh", "AllowNewsAndInterests", 0)),
        ("onedrive", _dw(f"{_WIN_POLICIES}\\OneDrive", "DisableFileSyncNGSC", 1)),
        ("edge_telemetry", _dw(f"{_POLICIES}\\Edge", "DiagnosticData", 0)),
        ("find_my_device", _dw(f"{_POLICIES}\\FindMyDevice", "AllowFindMyDevice", 0)),
        ("tips", _dw(f"{_WIN_POLICIES}\\CloudContent", "DisableSoftLanding", 1)),
    ]
    if version not in _AI_RELEASES:
        machine.append(
            ("cortana", _dw(f"{_WIN_POLICIES}\\Windows Search", "AllowCortana", 0))
        )
    machine = [step for key, step in machine if on[key]]
    user = [entry for key, entry in user if on[key]]
    if not machine and not user:
        return []
    out = [f"Log 'privacy {level}'"] + machine
    if user:
        # new accounts copy the default user profile
        hive = f"HKU\\{ident}-default"
        # OOBE may hold the file for a moment (it copies the profile for its
        # own account); without the hive every switch below would be lost
        out += [
            f"$hive='{hive}'; " '$ntu="$env:SystemDrive\\Users\\Default\\NTUSER.DAT"',
            "foreach($i in 1..20){reg.exe load $hive $ntu|Out-Null; "
            "if(-not $LASTEXITCODE){break}; Start-Sleep -Seconds 15}",
            "if($LASTEXITCODE){Log ('default user hive not loaded ('+"
            "$LASTEXITCODE+'), per-user privacy switches skipped')}else{",
        ]
        for entry in user:
            key, name, value = entry.split("|")
            out.append(_dw(f"{hive}\\{key}", name, int(value)))
        out.append(
            "[gc]::Collect(); reg.exe unload $hive|Out-Null; "
            "if($LASTEXITCODE){Log 'default user hive not unloaded'}}"
        )
    return out


def _bootstrap_ps1(ident, scripts_dir, task, profile, tgt, agent_ps1):
    caps = tgt["capabilities"]
    server = tgt["defaults"]["server"]
    log = f"$env:SystemRoot\\Temp\\{ident}-bootstrap.log"
    parts = [
        "$ErrorActionPreference='Continue'",
        f"$dir='{scripts_dir}'",
        f'$log="{log}"',
        "function Log($m){($(Get-Date -Format s)+' '+$m)|Out-File -Append $log}",
        "function SetDw($k,$n,$v){reg.exe add $k /v $n /t REG_DWORD /d $v /f|Out-Null}",
        "Log 'bootstrap start'",
        # the task runs again after a reboot; the policies only once
        "$done=Join-Path $dir 'policies.done'",
        "if(-not (Test-Path $done)){",
    ]

    debloat = profile.get("debloat", {})
    on = privacy_switches(tgt, profile)
    if on["consumer_content"]:
        parts.append(
            "Log 'consumer features off'; "
            + _dw(f"{_WIN_POLICIES}\\CloudContent", "DisableWindowsConsumerFeatures", 1)
        )
    appx = list(debloat.get("appx", []))
    version = profile.get("general", {}).get("version") or tgt["defaults"]["version"]
    if on["copilot"] and version in ("24H2", "25H2", "26H2"):
        appx.append(_CP_APP)
    for name in dict.fromkeys(appx):
        parts.append(
            f"Log 'remove appx {name}'; "
            f"Get-AppxPackage -AllUsers '{name}' -ErrorAction SilentlyContinue"
            "|Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue; "
            f"Get-AppxProvisionedPackage -Online|Where-Object DisplayName -eq '{name}'"
            "|Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue"
        )

    level = telemetry_level(profile, caps)
    if level is not None:
        parts.append(
            f"Log 'telemetry {level}'; "
            + _dw(f"{_WIN_POLICIES}\\DataCollection", "AllowTelemetry", level)
        )
    parts += _privacy_ps1(tgt, profile, ident)

    firewall = profile.get("firewall", {})
    if "firewall" in profile:
        state = "on" if firewall.get("on", True) else "off"
        parts.append(
            f"Log 'firewall {state}'; "
            f"netsh advfirewall set allprofiles state {state}|Out-Null"
        )
        for rule in firewall.get("allow", []):
            port, proto = rule.split("/")
            parts.append(
                f"New-NetFirewallRule -DisplayName '{ident} {rule}' -Direction "
                f"Inbound -Action Allow -Protocol {proto.upper()} -LocalPort {port}"
                "|Out-Null"
            )

    remote = profile.get("remote", {})
    if remote.get("rdp"):
        nla = 1 if remote.get("nla", True) else 0
        parts.append(
            "Log 'rdp on'; "
            "Set-ItemProperty -Path "
            "'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' "
            "-Name fDenyTSConnections -Value 0; "
            "Set-ItemProperty -Path ('HKLM:\\System\\CurrentControlSet\\Control\\"
            "Terminal Server\\WinStations\\RDP-Tcp') -Name UserAuthentication "
            f"-Value {nla}; "
            "Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' "
            "-ErrorAction SilentlyContinue"
        )

    parts.append("New-Item -ItemType File $done|Out-Null}")

    # the agent step repeats until the agent is registered (its AgentPK is
    # set); the setup program of a failed try makes the install script skip,
    # so later tries enroll with the installed program and the signed token
    ids = agent_ident()
    # the resolver and the server port are not ready on the first boot; wait before each try
    api = signing.api_url().replace("'", "''")
    parts += [
        f"$agent=Join-Path $dir '{ident}-agent.ps1'",
        f"$jws=Join-Path $dir '{ident}-enroll.jws'",
        f"$exe='{ids['identWinProgPath']}\\{ids['identWinExe']}'",
        f"$key='HKLM:\\SOFTWARE\\{ids['identWinRegKey']}'",
        "function Enrolled{[bool](Get-ItemProperty $key -Name AgentPK "
        "-ErrorAction SilentlyContinue)}",
        "while(-not (Enrolled)){",
        f"$u=[uri]'{api}'",
        "for($i=0;$i -lt 60;$i++){try{[void](Resolve-DnsName -Name $u.Host -ErrorAction Stop);"
        "$c=New-Object Net.Sockets.TcpClient;$c.Connect($u.Host,$u.Port);$c.Close();break}"
        "catch{Log ('waiting for '+$u.Host+' '+$u.Port+' ('+$i+')');Start-Sleep -Seconds 5}}",
        "Log 'install agent'",
        "try{if(Test-Path $exe){$rc=(Start-Process -FilePath $exe -ArgumentList "
        "@('-m','install','-enroll',\"`\"$jws`\"\",'-silent') -Wait -PassThru)"
        ".ExitCode}else{$global:LASTEXITCODE=0; & $agent; $rc=$LASTEXITCODE}}"
        "catch{$rc=$_.Exception.Message}",
        "if(Enrolled){break}",
        "Log ('agent not enrolled ('+$rc+'), next try in 15 minutes')",
        "Start-Sleep -Seconds 900",
        "}",
        "Log 'agent enrolled'",
    ]
    ssh = profile.get("ssh", {})
    if ssh.get("enable"):
        # after enrollment the network is up for the Feature on Demand
        parts += _ssh_ps1(ssh)

    encryption = profile.get("encryption", {})
    if caps.get("bitlocker") and encryption.get("bitlocker"):
        if server:
            parts.append(
                "Log 'bitlocker feature'; "
                "$f=Get-WindowsFeature BitLocker -ErrorAction SilentlyContinue; "
                "if($f -and -not $f.Installed){"
                "Install-WindowsFeature BitLocker -IncludeAllSubFeature "
                "-Restart -ErrorAction SilentlyContinue; "
                "Log 'reboot for bitlocker feature'; return}"
            )
        parts.append(
            "Log 'bitlocker on'; "
            "try{Enable-BitLocker -MountPoint C: -RecoveryPasswordProtector "
            "-SkipHardwareTest -ErrorAction Stop; "
            "Add-BitLockerKeyProtector -MountPoint C: -TpmProtector "
            "-ErrorAction SilentlyContinue}"
            "catch{Log ('bitlocker failed: '+$_.Exception.Message)}"
        )

    uwf = profile.get("uwf", {})
    if caps.get("uwf") and uwf.get("enabled"):
        prog = ids["identWinProgPath"]
        pdata = ids["identWinProgData"]
        regkey = ids["identWinRegKey"]
        parts.append(
            "Log 'uwf enable'; "
            "dism /online /enable-feature /featurename:Client-UnifiedWriteFilter "
            "/norestart|Out-Null; "
            f"uwfmgr file add-exclusion '{prog}'|Out-Null; "
            f"uwfmgr file add-exclusion '{pdata}'|Out-Null; "
            "uwfmgr file add-exclusion 'C:\\Program Files\\Mesh Agent'|Out-Null; "
            f"uwfmgr registry add-exclusion 'HKLM\\SOFTWARE\\{regkey}'|Out-Null; "
            "uwfmgr filter enable|Out-Null; "
            "uwfmgr volume protect C:|Out-Null"
        )

    parts.append("Log 'cleanup'")
    # the processed answer file still carries the embedded files
    parts.append(
        'try{$p="$env:SystemRoot\\Panther\\unattend.xml";$u=[xml]::new();'
        "$u.Load($p);$e=$u.unattend.Extensions;if($e){"
        "[void]$u.DocumentElement.RemoveChild($e);$u.Save($p)}}"
        "catch{Log ('payload cleanup failed: '+$_.Exception.Message)}"
    )
    parts.append(f"schtasks /Delete /TN '{task}' /F|Out-Null")
    parts.append("Remove-Item -Recurse -Force $dir -ErrorAction SilentlyContinue")
    # the agent setup from the ISO ($OEM$\$1) carries the enrollment token
    parts.append(
        "Remove-Item -Recurse -Force (Join-Path $env:SystemDrive 'ulrmm') "
        "-ErrorAction SilentlyContinue"
    )
    parts.append("Log 'bootstrap done'")
    return "\n".join(parts) + "\n"


_SSH_RULE = "OpenSSH-Server-In-TCP"


def _ssh_ps1(ssh: dict) -> list:
    auth = ssh.get("auth", "key")
    pubkey = "yes" if auth in ("key", "both") else "no"
    password = "yes" if auth in ("password", "both") else "no"
    keys = ssh_keys(ssh.get("authorized_keys", "")) if pubkey == "yes" else []
    out = [
        "Log 'ssh server'",
        "if(-not (Get-Service sshd -ErrorAction SilentlyContinue)){try{"
        "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 "
        "-ErrorAction Stop|Out-Null}"
        "catch{Log ('ssh install failed: '+$_.Exception.Message)}}",
        "if(Get-Service sshd -ErrorAction SilentlyContinue){",
        # the first start writes the host keys and sshd_config
        "Set-Service sshd -StartupType Automatic; Start-Service sshd",
        "$s=Join-Path $env:ProgramData 'ssh'",
    ]
    if keys:
        # administrators sign in with this file; sshd ignores it unless only
        # SYSTEM and Administrators (SIDs, any language) have access
        out += [
            "$ak=Join-Path $s 'administrators_authorized_keys'",
            "[IO.File]::WriteAllText($ak,(@'\n" + "\n".join(keys) + '\n\'@)+"`n")',
            "icacls $ak /inheritance:r /grant:r '*S-1-5-32-544:F' '*S-1-5-18:F'"
            "|Out-Null",
        ]
    out += [
        # the first match wins in sshd_config, so the choice goes on top
        "$c=Join-Path $s 'sshd_config'",
        "$l=@(Get-Content $c|Where-Object{$_ -notmatch "
        "'^\\s*#?\\s*(PubkeyAuthentication|PasswordAuthentication)\\s'})",
        "Set-Content -Encoding ascii -Path $c -Value (@("
        f"'PubkeyAuthentication {pubkey}','PasswordAuthentication {password}')+$l)",
        "Restart-Service sshd",
        f"if(Get-NetFirewallRule -Name '{_SSH_RULE}' -ErrorAction SilentlyContinue)"
        f"{{Enable-NetFirewallRule -Name '{_SSH_RULE}'}}else{{"
        f"New-NetFirewallRule -Name '{_SSH_RULE}' -DisplayName 'OpenSSH Server (sshd)' "
        "-Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22"
        "|Out-Null}",
        "}else{Log 'ssh server not installed'}",
    ]
    return out


def _setup_complete_cmd(task: str) -> str:
    return "@echo off\r\n" f'schtasks /Run /TN "{task}" >nul 2>&1\r\n' "exit /b 0\r\n"


def _add_international(s, general, arch, winpe=False):
    # the WinPE component sets Setup's own language; the plain one, in
    # specialize and oobeSystem, the installed system's and OOBE's
    name = "Microsoft-Windows-International-Core" + ("-WinPE" if winpe else "")
    intl = _component(s, name, arch)
    locale = general.get("locale", _DEFAULT_LOCALE)
    ui = general.get("ui_language", _DEFAULT_LOCALE)
    if winpe:
        setup_ui = _sub(intl, "SetupUILanguage")
        _sub(setup_ui, "UILanguage", ui)
    _sub(intl, "InputLocale", general.get("keyboard", _DEFAULT_KEYBOARD))
    _sub(intl, "SystemLocale", locale)
    _sub(intl, "UILanguage", ui)
    _sub(intl, "UserLocale", locale)


def _add_windows_pe(root, tgt, general, disk, arch):
    s = _sub(root, "settings", pass_="windowsPE")
    _add_international(s, general, arch, winpe=True)

    setup = _component(s, "Microsoft-Windows-Setup", arch)
    if disk.get("wipe", True):
        dcfg = _sub(setup, "DiskConfiguration")
        d = _sub(dcfg, "Disk")
        _wcm(d)
        _sub(d, "DiskID", str(disk.get("disk", 0)))
        _sub(d, "WillWipeDisk", "true")
        cc = _sub(d, "CreatePartitions")
        for order, (ptype, size) in enumerate(
            (("EFI", "260"), ("MSR", "128"), ("Primary", None)), start=1
        ):
            p = _sub(cc, "CreatePartition")
            _wcm(p)
            _sub(p, "Order", str(order))
            _sub(p, "Type", ptype)
            if size:
                _sub(p, "Size", size)
            else:
                _sub(p, "Extend", "true")
        mc = _sub(d, "ModifyPartitions")
        for order, (pid, fmt, label, letter, ptype) in enumerate(
            (
                (1, "FAT32", "System", None, "EFI"),
                (2, None, None, None, "MSR"),
                (3, "NTFS", "Windows", "C", "Primary"),
            ),
            start=1,
        ):
            m = _sub(mc, "ModifyPartition")
            _wcm(m)
            _sub(m, "Order", str(order))
            _sub(m, "PartitionID", str(pid))
            if fmt:
                _sub(m, "Format", fmt)
            if label:
                _sub(m, "Label", label)
            if letter:
                _sub(m, "Letter", letter)

    data = _sub(setup, "ImageInstall")
    osimage = _sub(data, "OSImage")
    install_to = _sub(osimage, "InstallTo")
    _sub(install_to, "DiskID", str(disk.get("disk", 0)))
    _sub(install_to, "PartitionID", "3")
    img_name = _image_name(tgt, general)
    meta = _sub(osimage, "InstallFrom")
    md = _sub(meta, "MetaData")
    _wcm(md)
    _sub(md, "Key", "/IMAGE/NAME")
    _sub(md, "Value", img_name)
    if general.get("image_index"):
        md2 = _sub(meta, "MetaData")
        _wcm(md2)
        _sub(md2, "Key", "/IMAGE/INDEX")
        _sub(md2, "Value", str(general["image_index"]))
    udata = _sub(setup, "UserData")
    _sub(udata, "AcceptEula", "true")
    pk = _sub(udata, "ProductKey")
    _sub(pk, "Key", "")


def _add_specialize(root, general, profile, arch):
    s = _sub(root, "settings", pass_="specialize")
    _add_international(s, general, arch)
    shell = _component(s, "Microsoft-Windows-Shell-Setup", arch)
    if general.get("hostname"):
        _sub(shell, "ComputerName", general["hostname"])
    _sub(shell, "TimeZone", _win_tz(general.get("timezone", _DEFAULT_TZ)))

    domain = profile.get("domain")
    if domain:
        join = _component(s, "Microsoft-Windows-UnattendedJoin", arch)
        ident_el = _sub(join, "Identification")
        creds = _sub(ident_el, "Credentials")
        _sub(creds, "Domain", domain["domain"])
        _sub(creds, "Username", domain["username"])
        _sub(creds, "Password", domain["password"])
        _sub(ident_el, "JoinDomain", domain["domain"])
        if domain.get("ou"):
            _sub(ident_el, "MachineObjectOU", domain["ou"])

    deploy = _component(s, "Microsoft-Windows-Deployment", arch)
    rs = _sub(deploy, "RunSynchronous")
    _run_sync(rs, 1, SPECIALIZE_CMD, "extract and register the first-boot task")


def _add_oobe(root, general, admin, server, arch, oobe_opts):
    s = _sub(root, "settings", pass_="oobeSystem")
    _add_international(s, general, arch)
    shell = _component(s, "Microsoft-Windows-Shell-Setup", arch)
    oobe = _sub(shell, "OOBE")
    _sub(oobe, "HideEULAPage", "true")
    _sub(oobe, "HideLocalAccountScreen", "true")
    _sub(oobe, "HideOnlineAccountScreens", "true")
    _sub(oobe, "HideWirelessSetupInOOBE", "true")
    if oobe_opts.get("skip_privacy_questions", True):
        # 3: the privacy page is not shown and its settings are off
        _sub(oobe, "ProtectYourPC", "3")
    _sub(oobe, "NetworkLocation", "Work")
    if server:
        ua = _sub(shell, "UserAccounts")
        ap = _sub(ua, "AdministratorPassword")
        _sub(ap, "Value", admin["password"])
        _sub(ap, "PlainText", "true")
    else:
        ua = _sub(shell, "UserAccounts")
        la = _sub(ua, "LocalAccounts")
        acct = _sub(la, "LocalAccount")
        _wcm(acct)
        pw = _sub(acct, "Password")
        _sub(pw, "Value", admin["password"])
        _sub(pw, "PlainText", "true")
        _sub(acct, "Name", admin["name"])
        _sub(acct, "Group", "Administrators")
        _sub(acct, "DisplayName", admin["name"])


def _add_payload(root, extract_ps1, files):
    # an element, not a comment, so it survives into Panther\unattend.xml
    ext = ET.SubElement(root, f"{{{XNS}}}Extensions")
    ET.SubElement(ext, f"{{{XNS}}}ExtractScript").text = extract_ps1
    for name, body in files:
        el = ET.SubElement(ext, f"{{{XNS}}}File", name=name)
        el.text = base64.b64encode(body.encode("utf-8")).decode("ascii")


def render(target_id: str, deployment, profile: dict):
    from .installers import WIN_ARCHES

    tgt = target(target_id)
    if tgt is None:
        raise serializers.ValidationError({"target": "unknown target"})
    if deployment.goarch not in WIN_ARCHES:
        raise serializers.ValidationError(
            {
                "deployment": f"There is no Windows agent build for "
                f"{deployment.goarch}; use an amd64 deployment."
            }
        )
    server = tgt["defaults"]["server"]
    # 386 deployments get the 64-bit media and agent
    arch = "amd64"

    general = dict(profile.get("general", {}))
    disk = dict(profile.get("disk", {"wipe": True, "disk": 0}))
    admin = dict(profile.get("admin", {}))

    secrets_out = []
    generated = {}

    # admin account: LAPS name by default, generate a password when none given
    laps_name, laps_len = _laps_admin(deployment)
    if not admin.get("name"):
        admin["name"] = laps_name
    if not admin.get("password"):
        admin["password"] = _gen_password(laps_len)
        generated["admin_password"] = admin["password"]
    secrets_out.append(admin["password"])
    if profile.get("domain"):
        secrets_out.append(profile["domain"]["password"])

    # the signed enrollment token rides inside the agent install script
    token = signing.mint_for_deployment(deployment)
    secrets_out.append(token)
    agent_ps1 = _agent_install_ps1(deployment, arch)

    ident, scripts_dir = _ident_dir()
    task = f"{agent_task_prefix()}Bootstrap"

    bootstrap = _bootstrap_ps1(ident, scripts_dir, task, profile, tgt, agent_ps1)
    extract = _extract_ps1(ident, scripts_dir, task)
    setup_complete = _setup_complete_cmd(task)

    embedded = [
        (f"{ident}-bootstrap.ps1", bootstrap),
        (f"{ident}-agent.ps1", agent_ps1),
        (f"{ident}-enroll.jws", token),
        ("SetupComplete.cmd", setup_complete),
    ]

    root = ET.Element(f"{{{NS}}}unattend")
    _add_windows_pe(root, tgt, general, disk, arch)
    _add_specialize(root, general, profile, arch)
    _add_oobe(root, general, admin, server, arch, profile.get("oobe", {}))
    _add_payload(root, extract, embedded)

    xml = _xml_bytes(root)

    files = [{"name": "autounattend.xml", "language": "xml", "content": xml}]
    files.append(
        {
            "name": f"{ident}-bootstrap.ps1",
            "language": "powershell",
            "content": bootstrap,
        }
    )
    files.append(
        {"name": f"{ident}-agent.ps1", "language": "powershell", "content": agent_ps1}
    )
    files.append(
        {"name": "SetupComplete.cmd", "language": "text", "content": setup_complete}
    )
    if profile.get("encryption", {}).get("bitlocker"):
        generated["note_recovery"] = (
            "BitLocker recovery password is generated on the device and "
            "escrowed to the server shortly after enrollment."
        )
    profile["_generated"] = generated
    return files, [s for s in secrets_out if s]


def _agent_install_ps1(deployment, arch):
    """The agent bootstrap PowerShell from S-PKG; patched out in tests until
    installers.py lands."""
    from . import installers

    text = installers.bootstrap_ps1(deployment, arch=arch)
    if _WEB_GET not in text:
        raise ValueError("the agent bootstrap has no download step to patch")
    return text.replace(_WEB_GET, _LOCAL_EXE, 1)


# the download step of the agent bootstrap; an exe in C:\ulrmm (put there by
# the ISO builder, $OEM$\$1, locked in specialize, deleted by the bootstrap)
# is installed instead and needs no sha256 check
_WEB_GET = """\
            Invoke-WebRequest -UseBasicParsing -Uri $downloadlink -OutFile $OutPath\\$output
            if ($sha256 -and (Get-FileHash -Algorithm SHA256 -LiteralPath $OutPath\\$output).Hash -ne $sha256) {
                throw "the download does not match its sha256 $sha256"
            }
"""

_LOCAL_EXE = """\
            $local = Get-ChildItem -Path (Join-Path $env:SystemDrive 'ulrmm\\*.exe') -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($local) {
                Copy-Item -LiteralPath $local.FullName -Destination $OutPath\\$output -Force
            } else {
                Invoke-WebRequest -UseBasicParsing -Uri $downloadlink -OutFile $OutPath\\$output
                if ($sha256 -and (Get-FileHash -Algorithm SHA256 -LiteralPath $OutPath\\$output).Hash -ne $sha256) {
                    throw "the download does not match its sha256 $sha256"
                }
            }
"""


def _xml_bytes(root) -> str:
    ET.register_namespace("", NS)
    ET.register_namespace("wcm", WCM)
    ET.register_namespace("ulrmm", XNS)
    _indent(root)
    body = ET.tostring(root, encoding="unicode")
    return '<?xml version="1.0" encoding="utf-8"?>\n' + body + "\n"


def _indent(elem, level=0):
    pad = "\n" + "  " * level
    if len(elem):
        if not (elem.text or "").strip():
            elem.text = pad + "  "
        for child in elem:
            _indent(child, level + 1)
            if not (child.tail or "").strip():
                child.tail = pad + "  "
        if not (elem[-1].tail or "").strip():
            elem[-1].tail = pad
    elif level and not (elem.tail or "").strip():
        elem.tail = pad


_README = """Windows unattended install
==========================

Setup reads autounattend.xml from the root of any removable drive. Give it
the file in one of these ways, then boot the target from the Windows media:

1. USB stick: copy autounattend.xml to the root of the Windows install stick.
2. Virtual machine, from Linux or macOS with xorriso installed:
     sh inject-xorriso.sh
   writes unattend.iso holding only autounattend.xml. Attach it as a second
   CD/DVD drive next to the unchanged Windows ISO. (xorriso cannot rewrite
   the Windows ISO itself: its files sit in UDF.)
3. One ISO with the answer file inside, on Windows with the Deployment Tools
   of the Windows ADK, in PowerShell as administrator:
     .\\inject-oscdimg.ps1 -Iso <Windows ISO> [-Out <new ISO>]

Setup partitions the disk set in the profile (all data on it is lost when
wiping is on) and installs Windows. On the next boot a SYSTEM start-up task
applies the baseline and installs the agent, retrying every 15 minutes until
the agent is enrolled; then it removes itself and its scripts. Its log is
C:\\Windows\\Temp\\{ident}-bootstrap.log.

The other files in this bundle are the scripts embedded in the answer file,
for review; Setup does not need them.

The answer file holds a short-lived enrollment token and the local admin
password in clear text. Treat it as a secret and delete it once the device
is enrolled.
"""

_INJECT_XORRISO = """#!/bin/sh
# writes unattend.iso (or $1) holding only autounattend.xml from this folder
set -e
cd "$(dirname "$0")"
command -v xorriso >/dev/null || { echo "xorriso is not installed" >&2; exit 1; }
xorriso -as mkisofs -o "${1:-unattend.iso}" -V UNATTEND -J -r autounattend.xml
"""

_INJECT_OSCDIMG = """# Rebuilds a Windows ISO with autounattend.xml from this folder in its root,
# bootable on BIOS and UEFI. Needs the Deployment Tools of the Windows ADK
# and an elevated PowerShell.
param(
    [Parameter(Mandatory = $true)][string]$Iso,
    [string]$Out = (Join-Path $PSScriptRoot 'windows-unattended.iso')
)
$ErrorActionPreference = 'Stop'
$oscdimg = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\\10\\Assessment and Deployment Kit\\Deployment Tools\\amd64\\Oscdimg\\oscdimg.exe'
if (-not (Test-Path $oscdimg)) { throw 'oscdimg.exe not found: install the Deployment Tools of the Windows ADK' }
# a path without spaces, oscdimg takes the boot files inside one argument
$work = Join-Path $env:SystemRoot ('Temp\\unattend-iso-' + [guid]::NewGuid().ToString('N'))
$image = Mount-DiskImage -ImagePath (Resolve-Path $Iso).Path -PassThru
try {
    $src = "$(($image | Get-Volume).DriveLetter):\\"
    New-Item -ItemType Directory $work | Out-Null
    Copy-Item -Recurse -Path (Join-Path $src '*') -Destination $work
} finally {
    Dismount-DiskImage -ImagePath $image.ImagePath | Out-Null
}
Copy-Item -Force (Join-Path $PSScriptRoot 'autounattend.xml') $work
$boot = "2#p0,e,b$work\\boot\\etfsboot.com#pEF,e,b$work\\efi\\microsoft\\boot\\efisys.bin"
& $oscdimg -m -o -u2 -udfver102 "-bootdata:$boot" $work $Out
$rc = $LASTEXITCODE
Remove-Item -Recurse -Force $work
if ($rc) { throw "oscdimg exit $rc" }
Write-Output "written: $Out"
"""


def bundle_extras(target_id: str, files):
    ident = agent_ident()["identWinRegKey"]
    readme = _README.format(ident=ident).replace("\n", "\r\n")
    return [
        ("README.txt", readme.encode()),
        ("inject-xorriso.sh", _INJECT_XORRISO.encode()),
        ("inject-oscdimg.ps1", _INJECT_OSCDIMG.replace("\n", "\r\n").encode()),
    ]
