# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""
OSV.dev client. Maps an agent onto an ecosystem, queries packages in
batches and keeps the advisory fields the dashboard shows.
"""

import math
import re
import time

import requests
from django.conf import settings
from django.utils.dateparse import parse_datetime

OSV_API = "https://api.osv.dev/v1"
TIMEOUT = 10
RETRIES = 2
BATCH_SIZE = 100
MAX_PAGES = 10

# OSV ecosystem -> inventory source (posix_packages.sh S lines) it matches
ECOSYSTEM_SOURCES = {
    "Debian": "dpkg",
    "Ubuntu": "dpkg",
    "Alpine": "apk",
    "Rocky Linux": "rpm",
    "AlmaLinux": "rpm",
    "openSUSE": "rpm",
}
# keyed by the source package name (openssh for openssh-server).
# AlmaLinux advisories use the binary package name
BY_SOURCE_PACKAGE = {"Debian", "Ubuntu", "Alpine", "Rocky Linux", "openSUSE"}

NO_ECOSYSTEM = "Windows and macOS have no OSV ecosystem."

RH_SEVERITY_RE = re.compile(r"(Critical|Important|Moderate|Low):")

LEVELS = {
    "critical": "critical",
    "important": "high",
    "high": "high",
    "moderate": "medium",
    "medium": "medium",
    "low": "low",
    "negligible": "low",
    "unimportant": "low",
}

CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
CVSS3 = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": CIA,
    "I": CIA,
    "A": CIA,
}
# privileges required, scope (unchanged, changed)
CVSS3_PR = {"N": (0.85, 0.85), "L": (0.62, 0.68), "H": (0.27, 0.5)}


def ecosystem(plat: str, operating_system: str | None) -> tuple[str | None, str]:
    """(OSV ecosystem, reason when there is none). The agent reports
    "<Platform> <version> <arch> <kernel>" with gopsutil's platform and version:
    lsb release for Ubuntu, /etc/debian_version, /etc/alpine-release, the
    redhat-release number, VERSION_ID of os-release for openSUSE."""
    if plat != "linux":
        return None, NO_ECOSYSTEM

    parts = (operating_system or "").split()
    distro = parts[0].lower() if parts else ""
    version = parts[1] if len(parts) > 1 else ""
    major = re.match(r"\d+", version)
    minor = re.match(r"(\d+)\.(\d+)", version)

    if distro == "debian" and major:
        return f"Debian:{major[0]}", ""
    if distro == "ubuntu" and minor:
        lts = ":LTS" if minor[2] == "04" and int(minor[1]) % 2 == 0 else ""
        return f"Ubuntu:{minor[0]}{lts}", ""
    if distro == "alpine" and minor:
        return f"Alpine:v{minor[0]}", ""
    if distro == "rocky" and major:
        return f"Rocky Linux:{major[0]}", ""
    if distro == "almalinux" and major:
        return f"AlmaLinux:{major[0]}", ""
    if distro == "opensuse-leap" and minor:
        return f"openSUSE:Leap {minor[0]}", ""
    if distro == "opensuse-tumbleweed":
        return "openSUSE:Tumbleweed", ""

    name = " ".join(parts[:2]) or "This Linux distribution"
    return None, f"{name} is not covered by OSV."


def packages(software, eco: str) -> set[tuple[str, str]]:
    """(name, version) of the inventory entries the ecosystem can match."""
    base = eco.split(":", 1)[0]
    source = ECOSYSTEM_SOURCES[base]
    ret = set()
    for item in software if isinstance(software, list) else []:
        if not isinstance(item, dict) or item.get("source") != source:
            continue
        name, version = item.get("name"), item.get("version")
        src = item.get("source_name"), item.get("source_version")
        if base in BY_SOURCE_PACKAGE and all(isinstance(v, str) and v for v in src):
            name, version = src
        if isinstance(name, str) and isinstance(version, str) and name and version:
            # dpkg names multi-arch packages with the architecture, libc6:amd64
            ret.add((name.split(":", 1)[0][:255], version[:255]))
    return ret


def osv_request(method: str, path: str, body: dict | None = None) -> dict:
    """HTTP calls to OSV go through here. Server errors are retried."""
    headers = {"User-Agent": f"ulrmm/{settings.ULRMM_VERSION}"}
    attempt = 0
    while True:
        r = requests.request(
            method, f"{OSV_API}/{path}", json=body, headers=headers, timeout=TIMEOUT
        )
        if r.status_code >= 500 and attempt < RETRIES:
            attempt += 1
            time.sleep(attempt)
            continue
        r.raise_for_status()
        return r.json()


def query_batch(keys: list[tuple[str, str, str]]) -> dict[tuple, list[dict]]:
    """keys are (ecosystem, name, version), at most BATCH_SIZE.
    Returns key -> [{"id", "modified"}]. Raises on any error."""
    queries = [
        {"package": {"ecosystem": eco, "name": name}, "version": version}
        for eco, name, version in keys
    ]
    found: dict[tuple, list[dict]] = {key: [] for key in keys}
    pending = list(range(len(keys)))
    # a package with more than 1000 vulns, or a batch with more than 3000, pages
    for _ in range(MAX_PAGES):
        data = osv_request(
            "POST", "querybatch", {"queries": [queries[i] for i in pending]}
        )
        results = data.get("results") if isinstance(data, dict) else None
        if not isinstance(results, list) or len(results) != len(pending):
            raise ValueError("unexpected querybatch answer")

        next_pending = []
        for i, res in zip(pending, results):
            res = res if isinstance(res, dict) else {}
            for v in res.get("vulns") or []:
                if isinstance(v, dict) and isinstance(v.get("id"), str):
                    found[keys[i]].append(
                        {"id": v["id"][:100], "modified": str(v.get("modified", ""))}
                    )
            if token := res.get("next_page_token"):
                queries[i] = {**queries[i], "page_token": token}
                next_pending.append(i)
        pending = next_pending
        if not pending:
            break
    return found


def parse_time(value):
    try:
        return parse_datetime(value) if isinstance(value, str) else None
    except ValueError:
        return None


def _roundup(value: float) -> float:
    # CVSS 3.1 Roundup, avoids float artefacts like 4.000000001 -> 4.1
    i = round(value * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_base_score(vector) -> float | None:
    if not isinstance(vector, str) or not vector.startswith("CVSS:3."):
        return None
    try:
        m = dict(part.split(":", 1) for part in vector.split("/")[1:])
        if m["S"] not in ("U", "C"):
            return None
        changed = m["S"] == "C"
        iss = 1 - (1 - CIA[m["C"]]) * (1 - CIA[m["I"]]) * (1 - CIA[m["A"]])
        exploit = (
            8.22
            * CVSS3["AV"][m["AV"]]
            * CVSS3["AC"][m["AC"]]
            * CVSS3_PR[m["PR"]][changed]
            * CVSS3["UI"][m["UI"]]
        )
    except (KeyError, ValueError):
        return None

    if changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0
    return _roundup(min((1.08 if changed else 1) * (impact + exploit), 10))


def _severity_text(data: dict, summary: str) -> str:
    db = data.get("database_specific")
    if isinstance(db, dict) and isinstance(db.get("severity"), str):
        return db["severity"]
    for s in data.get("severity") or []:
        if isinstance(s, dict) and s.get("type") == "Ubuntu":
            return str(s.get("score", ""))
    # Rocky Linux and AlmaLinux advisories start with the Red Hat rating
    if m := RH_SEVERITY_RE.match(summary):
        return m[1]
    for a in data.get("affected") or []:
        spec = a.get("ecosystem_specific") if isinstance(a, dict) else None
        if isinstance(spec, dict):
            for key in ("severity", "urgency"):
                if isinstance(spec.get(key), str):
                    return spec[key]
    return ""


def level(score: float | None, text: str) -> str:
    if score:
        if score >= 9:
            return "critical"
        if score >= 7:
            return "high"
        return "medium" if score >= 4 else "low"
    return LEVELS.get(text.lower().rstrip("*").strip(), "unknown")


def parse_vuln(data: dict) -> dict:
    """Fields for vulns.Advisory from a GET /v1/vulns/<id> answer."""
    details = data.get("details") if isinstance(data.get("details"), str) else ""
    summary = data.get("summary") or details.strip().split("\n", 1)[0]
    summary = summary if isinstance(summary, str) else ""

    scores = [
        cvss3_base_score(s.get("score"))
        for s in data.get("severity") or []
        if isinstance(s, dict) and s.get("type") == "CVSS_V3"
    ]
    score = max((s for s in scores if s is not None), default=None)
    text = _severity_text(data, summary)

    fixed: dict[str, list[str]] = {}
    for a in data.get("affected") or []:
        pkg = a.get("package") if isinstance(a, dict) else None
        eco = pkg.get("ecosystem") if isinstance(pkg, dict) else None
        # SUSE advisories list every product, keep what an agent can match
        if not isinstance(eco, str) or eco.split(":", 1)[0] not in ECOSYSTEM_SOURCES:
            continue
        key = f"{eco}|{pkg.get('name', '')}"
        for rng in a.get("ranges") or []:
            if not isinstance(rng, dict) or rng.get("type") != "ECOSYSTEM":
                continue
            for event in rng.get("events") or []:
                version = event.get("fixed") if isinstance(event, dict) else None
                if isinstance(version, str) and version not in fixed.get(key, []):
                    fixed.setdefault(key, []).append(version)

    return {
        "summary": summary[:500],
        "severity": text[:32],
        "score": score,
        "level": level(score, text),
        "fixed": fixed,
        "modified": parse_time(data.get("modified")),
    }
