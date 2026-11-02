# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""
MSRC security update documents (Windows KB -> CVE) and the NVD CVE api
(CPE name -> CVEs). Only https, every redirect hop included.
"""

import re
import time
from collections import deque
from urllib.parse import quote

import requests
from django.conf import settings

from .osv import parse_time

TIMEOUT = 20
MSRC_API = "https://api.msrc.microsoft.com/cvrf/v3.0"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_PAGE = 2000
NVD_MAX_PAGES = 3
# NVD allows 5 requests per 30 s without a key, 50 with one
NVD_WINDOW = 31

MONTH_RE = re.compile(r"\d{4}-[A-Z][a-z]{2}")
KB_RE = re.compile(r"(?:KB)?(\d{6,8})", re.IGNORECASE)
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
# MSRC threat type 3 is the severity, remediation type 2 the vendor fix
MSRC_SEVERITY = 3
MSRC_VENDOR_FIX = 2
SEVERITY_RANK = {"critical": 4, "important": 3, "moderate": 2, "low": 1}


def https_get(
    url: str, params=None, headers=None, ok=(), follow=True
) -> requests.Response:
    """Raises on http anywhere in the chain and on error codes not in ok.
    follow=False for a request that carries a key, no other host sees it."""
    r = requests.get(
        url,
        params=params,
        headers={"User-Agent": f"ulrmm/{settings.ULRMM_VERSION}", **(headers or {})},
        timeout=TIMEOUT,
        allow_redirects=follow,
    )
    for hop in (*r.history, r):
        if not hop.url.startswith("https://"):
            raise ValueError(f"redirected to {hop.url}")
    if 300 <= r.status_code < 400:
        raise ValueError(f"redirected with HTTP {r.status_code}")
    if r.status_code not in ok:
        r.raise_for_status()
    return r


def _value(obj) -> str:
    v = obj.get("Value") if isinstance(obj, dict) else None
    return v.strip() if isinstance(v, str) else ""


def msrc_months() -> list[tuple[str, object]]:
    """(month id, revised at) of the published documents, newest first."""
    data = https_get(f"{MSRC_API}/updates").json()
    docs = data.get("value") if isinstance(data, dict) else None
    out = []
    for d in docs if isinstance(docs, list) else []:
        month = d.get("ID") if isinstance(d, dict) else None
        if isinstance(month, str) and MONTH_RE.fullmatch(month):
            out.append(
                (month, d.get("InitialReleaseDate"), d.get("CurrentReleaseDate"))
            )
    out.sort(key=lambda m: str(m[1]), reverse=True)
    return [(month, parse_time(revised)) for month, _, revised in out]


def parse_cvrf(doc) -> dict[str, dict[str, dict]]:
    """kb digits -> {cve: {"id", "title", "severity", "score"}}"""
    kbs: dict[str, dict[str, dict]] = {}
    vulns = doc.get("Vulnerability") if isinstance(doc, dict) else None
    for v in vulns if isinstance(vulns, list) else []:
        cve = v.get("CVE") if isinstance(v, dict) else None
        if not isinstance(cve, str) or not CVE_RE.fullmatch(cve):
            continue

        severity = ""
        for t in v.get("Threats") or []:
            if isinstance(t, dict) and t.get("Type") == MSRC_SEVERITY:
                text = _value(t.get("Description"))
                if SEVERITY_RANK.get(text.lower(), 0) > SEVERITY_RANK.get(
                    severity.lower(), 0
                ):
                    severity = text
        scores = [
            s.get("BaseScore")
            for s in v.get("CVSSScoreSets") or []
            if isinstance(s, dict) and isinstance(s.get("BaseScore"), (int, float))
        ]
        info = {
            "id": cve,
            "title": _value(v.get("Title"))[:500],
            "severity": severity[:32],
            "score": float(max(scores)) if scores else None,
        }
        for rem in v.get("Remediations") or []:
            if not isinstance(rem, dict) or rem.get("Type") != MSRC_VENDOR_FIX:
                continue
            if m := KB_RE.fullmatch(_value(rem.get("Description"))):
                kbs.setdefault(m[1], {})[cve] = info
    return kbs


def msrc_document(month: str) -> dict[str, dict[str, dict]]:
    doc = https_get(
        f"{MSRC_API}/cvrf/{quote(month)}", headers={"Accept": "application/json"}
    ).json()
    return parse_cvrf(doc)


def parse_nvd(data, cpe: str) -> list[dict]:
    """[{"id", "summary", "score", "severity", "fixed"}] of one NVD answer.
    fixed lists the versionEndExcluding values of this product's criteria."""
    prefix = ":".join(cpe.split(":")[:5]) + ":"
    out = []
    items = data.get("vulnerabilities") if isinstance(data, dict) else None
    for item in items if isinstance(items, list) else []:
        cve = item.get("cve") if isinstance(item, dict) else None
        if not isinstance(cve, dict) or cve.get("vulnStatus") == "Rejected":
            continue
        cve_id = cve.get("id")
        if not isinstance(cve_id, str) or not CVE_RE.fullmatch(cve_id):
            continue

        summary = ""
        for d in cve.get("descriptions") or []:
            if isinstance(d, dict) and d.get("lang") == "en":
                summary = str(d.get("value") or "")
                break

        score, severity = None, ""
        metrics = cve.get("metrics") if isinstance(cve.get("metrics"), dict) else {}
        for key in ("cvssMetricV31", "cvssMetricV30"):
            for m in metrics.get(key) or []:
                cvss = m.get("cvssData") if isinstance(m, dict) else None
                s = cvss.get("baseScore") if isinstance(cvss, dict) else None
                if isinstance(s, (int, float)) and (score is None or s > score):
                    score, severity = float(s), str(cvss.get("baseSeverity") or "")
            if score is not None:
                break

        fixed = set()
        for conf in cve.get("configurations") or []:
            for node in conf.get("nodes") or [] if isinstance(conf, dict) else []:
                for m in node.get("cpeMatch") or [] if isinstance(node, dict) else []:
                    if (
                        isinstance(m, dict)
                        and m.get("vulnerable")
                        and str(m.get("criteria", "")).startswith(prefix)
                        and isinstance(m.get("versionEndExcluding"), str)
                    ):
                        fixed.add(m["versionEndExcluding"][:64])

        out.append(
            {
                "id": cve_id,
                "summary": summary.strip().split("\n", 1)[0][:500],
                "score": score,
                "severity": severity[:32],
                "fixed": sorted(fixed),
            }
        )
    return out


class Nvd:
    def __init__(self, api_key: str = ""):
        self.headers = {"apiKey": api_key} if api_key else {}
        self.sent: deque[float] = deque(maxlen=50 if api_key else 5)

    def _wait(self) -> None:
        if len(self.sent) == self.sent.maxlen:
            delay = self.sent[0] + NVD_WINDOW - time.monotonic()
            if delay > 0:
                time.sleep(delay)
        self.sent.append(time.monotonic())

    def cves(self, cpe: str) -> list[dict]:
        """CVEs that list this CPE name. A name NVD does not know has none."""
        out, start = [], 0
        for _ in range(NVD_MAX_PAGES):
            self._wait()
            r = https_get(
                NVD_API,
                params={
                    "cpeName": cpe,
                    "resultsPerPage": NVD_PAGE,
                    "startIndex": start,
                },
                headers=self.headers,
                ok=(404,),
                follow=False,
            )
            if r.status_code == 404:
                return []
            data = r.json()
            out.extend(parse_nvd(data, cpe))
            per_page = data.get("resultsPerPage") if isinstance(data, dict) else 0
            start += per_page if isinstance(per_page, int) else 0
            total = data.get("totalResults") if isinstance(data, dict) else 0
            if not per_page or not isinstance(total, int) or start >= total:
                break
        return out
