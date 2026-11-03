# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""
Microsoft Update Catalog lookups for the drivers of Windows agents.
There is no API: the search page is parsed and anything unexpected counts
as "catalog unavailable", never as "no update".
"""

import base64
import datetime as dt
import html
import json
import re
import time
from urllib.parse import urljoin, urlsplit

import requests
from django.conf import settings
from django.utils import timezone as djangotime

from remote.utils import version_key

from .models import DriverCatalog

CATALOG = "https://www.catalog.update.microsoft.com"
CATALOG_HOSTS = ("catalog.update.microsoft.com",)
DOWNLOAD_HOSTS = ("windowsupdate.com", "microsoft.com")
TIMEOUT = (10, 30)
# seconds between two requests to the catalog
SPACING = 2.0
MAX_HOPS = 5
# the search box takes 100 characters
MAX_KEY = 100
# same version, other OEM/OS variants tried for the architecture
MAX_CANDIDATES = 5

UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_ROW_RE = re.compile(
    r'<tr id="([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})_R(\d+)"'
    r"(.*?)</tr>",
    re.S,
)
_TAG_RE = re.compile(r"<[^>]+>")
_KEY_CHARS_RE = re.compile(r"[A-Z0-9_&\\.-]+")
_REV_RE = re.compile(r"&REV_[0-9A-F]+")
_SHORT_KEYS = (
    re.compile(r"PCI\\VEN_[0-9A-F]{4}&DEV_[0-9A-F]{4}"),
    re.compile(r"USB\\VID_[0-9A-F]{4}&PID_[0-9A-F]{4}"),
    re.compile(r"HDAUDIO\\FUNC_[0-9A-F]{2}&VEN_[0-9A-F]{4}&DEV_[0-9A-F]{4}"),
)
_PREFIXES = ("PCI\\VEN_", "USB\\VID_", "HDAUDIO\\FUNC_", "ACPI\\")
# ACPI\PNP0A08 and ACPI\ACPI0010 are inbox devices
_ACPI_INBOX = ("ACPI\\PNP", "ACPI\\ACPI")
_BUILD_RE = re.compile(r"build (\d+)", re.IGNORECASE)
_LATER_RE = re.compile(r",\s*(?:version\s+)?([0-9A-Za-z]+) and later")
_DL_RE = re.compile(
    r"downloadInformation\[(\d+)\]\.files\[(\d+)\]\.(url|sha256|fileName)\s*=\s*'([^']*)'"
)

# "<tag> and later" -> first build of that release, per family
BUILDS = {
    "Windows 10": {
        "1607": 14393,
        "1709": 16299,
        "1803": 17134,
        "1809": 17763,
        "1903": 18362,
        "Vibranium": 19041,
        "21H2": 19044,
        "22H2": 19045,
    },
    "Windows 11": {
        "21H2": 22000,
        "22H2": 22621,
        "23H2": 22631,
        "24H2": 26100,
        "25H2": 26200,
    },
    # Server 2022 is 21H2 at build 20348, not the client's 22000
    "Windows Server": {
        "1607": 14393,
        "2016": 14393,
        "1709": 16299,
        "1803": 17134,
        "1809": 17763,
        "2019": 17763,
        "1903": 18362,
        "21H2": 20348,
        "2022": 20348,
        "23H2": 25398,
        "24H2": 26100,
        "2025": 26100,
    },
}

ARCH = {"arm64": "ARM64", "64": "AMD64", "32": "X86"}


class CatalogError(Exception):
    pass


def host_ok(url: str, hosts) -> bool:
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return False
    host = (parts.hostname or "").lower()
    return (
        parts.scheme == "https"
        and port in (None, 443)
        and any(host == h or host.endswith("." + h) for h in hosts)
    )


def fetch(method: str, url: str, hosts, *, user_agent="", **kw) -> requests.Response:
    """Follows redirects by hand so every hop is https on one of hosts
    before it is contacted. A redirected POST is an error."""
    headers = {"User-Agent": user_agent or f"ulrmm/{settings.ULRMM_VERSION}"}
    headers.update(kw.pop("headers", None) or {})
    kw.setdefault("timeout", TIMEOUT)
    for _ in range(MAX_HOPS + 1):
        if not host_ok(url, hosts):
            raise CatalogError(f"refused to fetch {url[:200]}")
        r = requests.request(method, url, headers=headers, allow_redirects=False, **kw)
        if r.status_code not in (301, 302, 303, 307, 308):
            return r
        r.close()
        # the Location carries its own query
        kw.pop("params", None)
        if method != "GET":
            raise CatalogError(f"{method} was redirected")
        url = urljoin(url, r.headers.get("Location", ""))
    raise CatalogError("too many redirects")


class Fetcher:
    """Catalog requests, SPACING seconds apart."""

    def __init__(self):
        self.last = 0.0
        self.agent = f"ulrmm/{settings.ULRMM_VERSION} (driver catalog)"

    def _call(self, method, url, **kw) -> str:
        wait = self.last + SPACING - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        try:
            r = fetch(method, url, CATALOG_HOSTS, user_agent=self.agent, **kw)
        except requests.RequestException as e:
            raise CatalogError(type(e).__name__) from e
        finally:
            self.last = time.monotonic()
        if r.status_code != 200:
            raise CatalogError(f"HTTP {r.status_code}")
        return r.text

    def search(self, key: str) -> list[dict]:
        return parse_search(
            self._call("GET", f"{CATALOG}/Search.aspx", params={"q": key})
        )

    def arch(self, update_id: str) -> str:
        return parse_arch(
            self._call(
                "GET",
                f"{CATALOG}/ScopedViewInline.aspx",
                params={"updateid": update_id},
            )
        )

    def download(self, update_id: str) -> dict:
        item = {"size": 0, "languages": "", "uidInfo": update_id, "updateID": update_id}
        form = {
            "updateIDs": json.dumps([item]),
            **dict.fromkeys(
                (
                    "updateIDsBlockedForImport",
                    "wsusApiPresent",
                    "contentImport",
                    "sku",
                    "serverName",
                    "ssl",
                    "portNumber",
                    "version",
                ),
                "",
            ),
        }
        return parse_download(
            self._call("POST", f"{CATALOG}/DownloadDialog.aspx", data=form)
        )


def search_keys(device_id: str) -> list[str]:
    """Catalog search terms for an instance path: the hardware id without
    the revision, then the short vendor/device form."""
    if not isinstance(device_id, str) or "\\" not in device_id:
        return []
    hwid = _REV_RE.sub("", device_id.rsplit("\\", 1)[0].upper())
    if not hwid.startswith(_PREFIXES) or hwid.startswith(_ACPI_INBOX):
        return []
    keys = [hwid]
    for pattern in _SHORT_KEYS:
        if m := pattern.match(hwid):
            keys.append(m.group())
    return [
        k
        for i, k in enumerate(keys)
        if len(k) <= MAX_KEY and _KEY_CHARS_RE.fullmatch(k) and k not in keys[:i]
    ]


def _text(value: str) -> str:
    return " ".join(html.unescape(_TAG_RE.sub(" ", value)).split())


def _date(value: str) -> str:
    try:
        return dt.datetime.strptime(value, "%m/%d/%Y").date().isoformat()
    except ValueError:
        return ""


def parse_search(page: str) -> list[dict]:
    """Rows of page 1, firmware dropped. CatalogError when the page is not
    a result table and not the no-result page."""
    if 'id="ctl00_catalogBody_updateMatches"' not in page:
        if 'id="ctl00_catalogBody_noResultText"' in page:
            return []
        raise CatalogError("catalog page not understood")
    entries = []
    for uid, n, body in _ROW_RE.findall(page):
        cells = dict(re.findall(rf'id="{uid}_C(\d)_R{n}"[^>]*>(.*?)</td>', body, re.S))
        title = _text(cells.get("1", ""))
        version = _text(cells.get("5", ""))
        date = _date(_text(cells.get("4", "")))
        if not (title and version and date):
            continue
        size = re.search(rf'id="{uid}_originalSize">\s*(\d+)\s*<', body)
        entries.append(
            {
                "update_id": uid,
                "title": title[:255],
                "products": _text(cells.get("2", ""))[:500],
                "classification": _text(cells.get("3", ""))[:64],
                "date": date,
                "version": version[:64],
                "size": int(size.group(1)) if size else 0,
            }
        )
    if not entries:
        raise CatalogError("catalog page not understood")
    return [e for e in entries if "firmware" not in e["classification"].lower()]


def parse_arch(page: str) -> str:
    m = re.search(r'<div id="archDiv">(.*?)</div>', page, re.S)
    if not m:
        raise CatalogError("details page not understood")
    return _text(m.group(1).rsplit("</span>", 1)[-1]).upper()


def parse_download(page: str) -> dict:
    """{"url", "sha256" (hex), "name"} of the one file of the update."""
    files: dict[tuple, dict] = {}
    for update, idx, key, value in _DL_RE.findall(page):
        files.setdefault((update, idx), {})[key] = html.unescape(value)
    if len(files) != 1:
        raise CatalogError(f"the download dialog lists {len(files)} files")
    f = next(iter(files.values()))
    try:
        sha = base64.b64decode(f.get("sha256", ""), validate=True)
    except ValueError:
        sha = b""
    url, name = f.get("url", ""), f.get("fileName", "")
    if len(sha) != 32:
        raise CatalogError("the download dialog has no sha256")
    if not host_ok(url, DOWNLOAD_HOSTS) or not urlsplit(url).path.lower().endswith(
        ".cab"
    ):
        raise CatalogError(f"unexpected download {url[:200]}")
    return {"url": url, "sha256": sha.hex(), "name": name or url.rsplit("/", 1)[-1]}


def os_target(operating_system: str) -> tuple[str, int | None]:
    """(family, build) from the agent's operating_system."""
    text = operating_system or ""
    m = _BUILD_RE.search(text)
    build = int(m.group(1)) if m else None
    if "server" in text.lower():
        return "Windows Server", build
    if build is not None:
        return ("Windows 11" if build >= 22000 else "Windows 10"), build
    return ("Windows 11" if "Windows 11" in text else "Windows 10"), None


def applicable(entry: dict, family: str, build: int | None) -> bool:
    products = str(entry.get("products", "")).replace(
        "Windows - Server", "Windows Server"
    )
    for item in re.split(r"(?=Windows)", products):
        if not item.startswith(family):
            continue
        m = _LATER_RE.search(item)
        need = BUILDS[family].get(m.group(1)) if m else None
        if need is None or build is None or build >= need:
            return True
    return False


def newest(entries: list, driver: dict, family: str, build: int | None) -> dict | None:
    """The highest applicable entry newer than the installed driver."""
    have = version_key(str(driver.get("version") or ""))
    date = str(driver.get("date") or "")
    best, best_key = None, None
    for e in entries:
        if not isinstance(e, dict) or not applicable(e, family, build):
            continue
        ver = version_key(str(e.get("version", "")))
        if ver is None:
            continue
        if have is not None:
            if ver <= have:
                continue
        elif not (date and str(e.get("date", "")) > date):
            continue
        key = (ver, str(e.get("date", "")))
        if best_key is None or key > best_key:
            best, best_key = e, key
    return best


def agent_arch(agent) -> str:
    if agent.goarch == "arm64":
        return ARCH["arm64"]
    return ARCH.get(agent.arch or "", "")


def arch_ok(listed: str, wanted: str) -> bool:
    return not listed or not wanted or wanted in re.split(r"[\s,;/]+", listed)


def inventory_keys(data) -> list[tuple[str, ...]]:
    """Distinct search key lists of one driver inventory."""
    drivers = data.get("drivers") if isinstance(data, dict) else None
    out = {}
    for d in drivers if isinstance(drivers, list) else []:
        if isinstance(d, dict) and (keys := search_keys(d.get("device_id"))):
            out[tuple(keys)] = None
    return list(out)


def _next_key(keys, i, cached) -> bool:
    """The short key is only searched when the full one found nothing."""
    if i == 0:
        return True
    prev = cached.get(keys[i - 1])
    return prev is not None and not prev.error and not prev.entries


def scan(
    key_lists, max_requests: int, fresh_ok, fresh_error, fetcher=None, step=None
) -> dict:
    """Searches the stale keys, oldest first. 3 errors in a row end the run."""
    fetcher = fetcher or Fetcher()
    now = djangotime.now()
    names = {k for keys in key_lists for k in keys}
    cached = {c.hwid: c for c in DriverCatalog.objects.filter(hwid__in=names)}
    never = dt.datetime.min.replace(tzinfo=dt.timezone.utc)

    def fresh(key) -> bool:
        row = cached.get(key)
        limit = fresh_error if row and row.error else fresh_ok
        return row is not None and now - row.checked < limit

    stats = {"requests": 0, "errors": 0, "stopped": ""}
    in_row = 0
    order = sorted(
        key_lists, key=lambda ks: cached[ks[0]].checked if ks[0] in cached else never
    )
    for n, keys in enumerate(order):
        if step:
            step(n, len(order))
        for i, key in enumerate(keys):
            if not _next_key(keys, i, cached):
                break
            if fresh(key):
                continue
            if stats["requests"] >= max_requests:
                stats["stopped"] = f"request limit {max_requests}"
                return stats
            stats["requests"] += 1
            old = cached.get(key)
            try:
                entries, error = fetcher.search(key), ""
            except CatalogError as e:
                entries, error = (old.entries if old else []), str(e)[:255]
            cached[key], _ = DriverCatalog.objects.update_or_create(
                hwid=key,
                defaults={
                    "checked": djangotime.now(),
                    "error": error,
                    "entries": entries,
                },
            )
            if not error:
                in_row = 0
                continue
            stats["errors"] += 1
            in_row += 1
            if in_row >= 3:
                stats["stopped"] = f"3 errors in a row, last: {error}"
                return stats
    return stats


def _pick(keys, cached, driver, family, build) -> tuple[dict | None, str, list]:
    """(newest entry or None, the key it came from, the keys looked at)."""
    used = []
    for i, key in enumerate(keys):
        if not _next_key(keys, i, cached):
            break
        used.append(key)
    for key in used:
        row = cached.get(key)
        if row and (e := newest(row.entries, driver, family, build)):
            return e, key, used
    return None, keys[0] if keys else "", used


SHOWN = ("version", "date", "title", "update_id", "size", "classification")


def _lookup(keys, cached, driver, family, build) -> dict:
    pick, query, used = _pick(keys, cached, driver, family, build)
    checks = [cached[k].checked if k in cached else None for k in used]
    errors = [cached[k].error for k in used if k in cached and cached[k].error]
    return {
        "catalog": (
            {**{f: pick.get(f) for f in SHOWN}, "query": query} if pick else None
        ),
        "catalog_checked": min(checks) if checks and None not in checks else None,
        "catalog_error": (
            f"Microsoft Update Catalog unavailable: {errors[0]}" if errors else ""
        ),
    }


def catalog_fields(agent, drivers: list) -> list[dict]:
    """catalog, catalog_checked and catalog_error per driver row."""
    keys = [search_keys(d.get("device_id")) for d in drivers]
    names = {k for ks in keys for k in ks}
    cached = {c.hwid: c for c in DriverCatalog.objects.filter(hwid__in=names)}
    family, build = os_target(agent.operating_system)
    return [_lookup(ks, cached, d, family, build) for ks, d in zip(keys, drivers)]


def candidates(agent, driver: dict) -> list[dict]:
    """The offered entry, then other variants of its version, to try in turn."""
    keys = search_keys(driver.get("device_id"))
    cached = {c.hwid: c for c in DriverCatalog.objects.filter(hwid__in=keys)}
    family, build = os_target(agent.operating_system)
    pick, query, _ = _pick(keys, cached, driver, family, build)
    if pick is None:
        return []
    same = [
        e
        for e in cached[query].entries
        if isinstance(e, dict)
        and e.get("version") == pick.get("version")
        and e.get("update_id") != pick.get("update_id")
        and applicable(e, family, build)
    ]
    return [pick, *same][:MAX_CANDIDATES]
