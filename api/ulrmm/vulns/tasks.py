# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import datetime as dt
import hashlib
import re
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote

from django.db import transaction
from django.db.models import Max
from django.utils import timezone as djangotime

from agents.models import Agent
from core.models import NVD_KEY_INFO, CoreSettings
from logs.models import DebugLog
from remote.utils import decrypt_secret, version_key
from software.models import InstalledSoftware
from ulrmm.celery import app
from ulrmm.constants import AGENT_DEFER, AgentPlat
from ulrmm.utils import redis_lock
from winupdate.models import WinUpdate

from . import cpe_map, feeds, osv
from .models import (
    Advisory,
    AgentScan,
    Finding,
    FindingStatus,
    Level,
    Lookup,
    MsrcMap,
    NvdLookup,
    Source,
)

LOOKUP_TTL = dt.timedelta(days=7)
FETCH_WORKERS = 8
# Windows and macOS: MSRC for pending Windows updates, NVD for known apps
PLAT_NAMES = {AgentPlat.WINDOWS: "Windows", AgentPlat.DARWIN: "macOS"}
SCANNED = (AgentPlat.LINUX, AgentPlat.WINDOWS, AgentPlat.DARWIN)
MSRC_MONTHS = 3
NVD_TTL = dt.timedelta(days=7)
# without an api key a lookup takes about 6 s
NVD_MAX_PER_RUN = 500
NOTIFY_LEVELS = (Level.CRITICAL, Level.HIGH)
NOTIFY_LINES = 20
# FreeBSD devices run pkg audit (VuXML) themselves during a package scan
FREEBSD = "FreeBSD"
VUXML_ID_RE = re.compile(r"/freebsd/([0-9a-f-]{36})\.html$")
# "< 1.9.5p2" or ">= 1.8.0 : < 1.9.12p1"
VUXML_FIX_RE = re.compile(r"(?:^|:)\s*<\s*([^\s<>=:]+)\s*$")
# the list comes from the device, not from a feed
MAX_AUDIT_ISSUES = 5000

Key = tuple[str, str, str]


def _lookups(keys: set[Key]) -> dict[Key, list[dict]]:
    """OSV answers for each (ecosystem, name, version), cached for LOOKUP_TTL.

    A key is absent when that query failed.
    """
    cutoff = djangotime.now() - LOOKUP_TTL
    names = defaultdict(set)
    for eco, name, _ in keys:
        names[eco].add(name)

    found: dict[Key, list[dict]] = {}
    for eco, eco_names in names.items():
        cached = Lookup.objects.filter(
            ecosystem=eco, name__in=eco_names, fetched_at__gte=cutoff
        ).values_list("ecosystem", "name", "version", "result")
        for e, n, v, result in cached:
            if (e, n, v) in keys:
                found[(e, n, v)] = result

    missing = sorted(keys - found.keys())
    for i in range(0, len(missing), osv.BATCH_SIZE):
        batch = missing[i : i + osv.BATCH_SIZE]
        try:
            answer = osv.query_batch(batch)
        except Exception as e:
            DebugLog.error(
                f"OSV query for {len(batch)} packages failed, they keep their findings: {e}"
            )
            continue

        now = djangotime.now()
        Lookup.objects.bulk_create(
            [
                Lookup(ecosystem=e, name=n, version=v, result=r, fetched_at=now)
                for (e, n, v), r in answer.items()
            ],
            update_conflicts=True,
            unique_fields=["ecosystem", "name", "version"],
            update_fields=["result", "fetched_at"],
        )
        found.update(answer)
    return found


def _fetch(vuln_id: str) -> dict | Exception:
    """Advisory fields, or the error. A bad payload fails this advisory alone."""
    try:
        return osv.parse_vuln(
            osv.osv_request("GET", f"vulns/{quote(vuln_id, safe=':')}")
        )
    except Exception as e:
        return e


def _advisories(vulns: dict[str, str]) -> dict[str, int]:
    """vulns is id -> modified, as querybatch listed them.

    Fetches advisories that are new or whose modified time moved.
    Returns id -> Advisory pk.
    """
    known = dict(
        Advisory.objects.filter(vuln_id__in=vulns).values_list("vuln_id", "modified")
    )
    stale = []
    for vuln_id, modified in vulns.items():
        listed = osv.parse_time(modified)
        if vuln_id not in known or (
            listed and (known[vuln_id] is None or listed > known[vuln_id])
        ):
            stale.append(vuln_id)

    with ThreadPoolExecutor(FETCH_WORKERS) as pool:
        answers = list(pool.map(_fetch, stale))

    now = djangotime.now()
    rows, errors = [], []
    for vuln_id, data in zip(stale, answers):
        if isinstance(data, Exception):
            errors.append(f"{vuln_id}: {data}")
            continue
        rows.append(Advisory(vuln_id=vuln_id, fetched_at=now, **data))

    if errors:
        DebugLog.error(
            f"{len(errors)} OSV advisories could not be fetched, first: {errors[0]}"
        )
    Advisory.objects.bulk_create(
        rows,
        batch_size=1000,
        update_conflicts=True,
        unique_fields=["vuln_id"],
        update_fields=[
            "summary",
            "severity",
            "score",
            "level",
            "fixed",
            "modified",
            "fetched_at",
        ],
    )
    return dict(Advisory.objects.filter(vuln_id__in=vulns).values_list("vuln_id", "pk"))


def notify(event: dict) -> None:
    # the notify app is optional here
    try:
        from notify.dispatch import dispatch
    except ImportError:
        return
    try:
        dispatch(event)
    except Exception as e:
        DebugLog.error(message=f"Vulnerability notification failed: {e}")


def ecosystem(agent: Agent) -> tuple[str | None, str]:
    """What an agent is checked as, or why it is not checked."""
    if agent.plat in PLAT_NAMES:
        return PLAT_NAMES[agent.plat], ""
    if agent.plat == AgentPlat.FREEBSD:
        return FREEBSD, ""
    return osv.ecosystem(agent.plat, agent.operating_system)


def _record(
    agent: Agent,
    source: str,
    current: dict[Key, str],
    advisories: dict[str, int],
    unchecked: set[tuple[str, str]],
) -> list[Finding]:
    """Findings of one source on one agent. current is (package, version,
    vuln id) -> ecosystem. A finding that is gone is fixed, unless its package
    could not be checked. Returns the open findings that are new or just got
    their advisory."""
    now = djangotime.now()
    existing = {
        (f.package, f.version, f.vuln_id): f
        for f in Finding.objects.filter(agent=agent, source=source)
    }
    # an ignored vuln stays ignored when its package moves to another version
    ignored = {
        (f.package, f.vuln_id)
        for f in existing.values()
        if f.status == FindingStatus.IGNORED
    }
    new, changed, advised = [], [], []
    for key, eco in current.items():
        f = existing.get(key)
        if f is None:
            new.append(
                Finding(
                    agent=agent,
                    source=source,
                    package=key[0],
                    version=key[1],
                    vuln_id=key[2],
                    ecosystem=eco,
                    advisory_id=advisories.get(key[2]),
                    status=(
                        FindingStatus.IGNORED
                        if (key[0], key[2]) in ignored
                        else FindingStatus.OPEN
                    ),
                    first_seen=now,
                    last_seen=now,
                )
            )
            continue
        f.last_seen = now
        f.ecosystem = eco
        if f.advisory_id is None and advisories.get(key[2]) is not None:
            advised.append(f)
        f.advisory_id = advisories.get(key[2], f.advisory_id)
        if f.status == FindingStatus.FIXED:
            f.status = FindingStatus.OPEN
        changed.append(f)

    for key, f in existing.items():
        if (
            key not in current
            and f.status != FindingStatus.FIXED
            and key[:2] not in unchecked
        ):
            f.status = FindingStatus.FIXED
            changed.append(f)

    Finding.objects.bulk_create(new, batch_size=1000)
    Finding.objects.bulk_update(
        changed, ["last_seen", "ecosystem", "advisory", "status"], batch_size=1000
    )
    return [f for f in new + advised if f.status == FindingStatus.OPEN]


def _apply(
    agent: Agent,
    eco: str,
    packages: set[tuple[str, str]],
    lookups: dict[Key, list[dict]],
    advisories: dict[str, int],
) -> list[Finding]:
    current: dict[Key, str] = {}
    unchecked = set()
    for name, version in packages:
        result = lookups.get((eco, name, version))
        if result is None:
            unchecked.add((name, version))
            continue
        current.update(((name, version, v["id"]), eco) for v in result)

    new = _record(agent, Source.OSV, current, advisories, unchecked)
    AgentScan.objects.update_or_create(
        agent=agent,
        defaults={
            "ecosystem": eco,
            "scanned_at": djangotime.now(),
            "packages": len(packages),
            "unchecked": len(unchecked),
        },
    )
    return new


def _notify_new(agent: Agent, new: list[Finding]) -> None:
    advisories = {
        pk: (level, fixed)
        for pk, level, fixed in Advisory.objects.filter(
            pk__in={f.advisory_id for f in new if f.advisory_id},
            level__in=NOTIFY_LEVELS,
        ).values_list("pk", "level", "fixed")
    }

    # only what an update can fix, the rest shows up under "No fix yet"
    def fixable(f) -> bool:
        got = (advisories[f.advisory_id][1] or {}).get(f"{f.ecosystem}|{f.package}")
        return isinstance(got, list) and bool(got)

    hits = [
        f
        for f in new
        if f.advisory_id in advisories and f.status == FindingStatus.OPEN and fixable(f)
    ]
    levels = {f.advisory_id: advisories[f.advisory_id][0] for f in hits}
    if not hits:
        return

    lines = [
        f"{f.vuln_id} ({levels[f.advisory_id]}) in {f.package} {f.version}".rstrip()
        for f in hits[:NOTIFY_LINES]
    ]
    if len(hits) > NOTIFY_LINES:
        lines.append(f"and {len(hits) - NOTIFY_LINES} more")
    ids = ",".join(sorted({f.vuln_id for f in hits}))
    notify(
        {
            "source": "vuln",
            "severity": (
                "error"
                if Level.CRITICAL in (levels[f.advisory_id] for f in hits)
                else "warning"
            ),
            "title": f"{len(hits)} new critical or high vulnerabilities "
            f"with an update on {agent.effective_name}",
            "body": "\n".join(lines),
            "agent": agent,
            "dedupe_key": f"vuln:{agent.agent_id}:"
            + hashlib.sha256(ids.encode()).hexdigest()[:16],
        }
    )


def _merge_advisories(details: dict[str, dict]) -> dict[str, int]:
    """MSRC and NVD details. An advisory that exists already, from OSV or an
    earlier run, gets the missing fields and this run's fixed versions."""
    now = djangotime.now()
    existing = {a.vuln_id: a for a in Advisory.objects.filter(vuln_id__in=details)}
    new, changed = [], []
    for vuln_id, data in details.items():
        a = existing.get(vuln_id)
        if a is None:
            new.append(Advisory(vuln_id=vuln_id, fetched_at=now, **data))
            continue
        before = (a.summary, a.severity, a.score, a.level, a.fixed)
        if a.score is None and data["score"] is not None:
            a.score, a.level = data["score"], data["level"]
        elif a.level == Level.UNKNOWN:
            a.level = data["level"]
        a.summary = a.summary or data["summary"]
        a.severity = a.severity or data["severity"]
        a.fixed = {**a.fixed, **data["fixed"]}
        if (a.summary, a.severity, a.score, a.level, a.fixed) != before:
            changed.append(a)

    Advisory.objects.bulk_create(new, batch_size=1000, ignore_conflicts=True)
    Advisory.objects.bulk_update(
        changed, ["summary", "severity", "score", "level", "fixed"], batch_size=1000
    )
    return dict(
        Advisory.objects.filter(vuln_id__in=details).values_list("vuln_id", "pk")
    )


def _detail(details: dict, vuln_id: str, info: dict, key: str, fixed: list) -> None:
    d = details.setdefault(
        vuln_id,
        {
            "summary": info.get("summary") or info.get("title") or "",
            "severity": info.get("severity") or "",
            "score": info.get("score"),
            "level": osv.level(info.get("score"), info.get("severity") or ""),
            "fixed": {},
        },
    )
    d["fixed"][key] = fixed


def _msrc_refresh() -> None:
    """Fetches the newest MSRC_MONTHS documents that are new or revised."""
    try:
        months = feeds.msrc_months()[:MSRC_MONTHS]
    except Exception as e:
        DebugLog.error(f"MSRC update list could not be fetched: {e}")
        return

    fetched = dict(MsrcMap.objects.values_list("month").annotate(at=Max("fetched_at")))
    for month, revised in months:
        if month in fetched and (revised is None or revised <= fetched[month]):
            continue
        try:
            kbs = feeds.msrc_document(month)
        except Exception as e:
            DebugLog.error(f"MSRC document {month} could not be fetched: {e}")
            continue
        now = djangotime.now()
        with transaction.atomic():
            MsrcMap.objects.filter(month=month).delete()
            MsrcMap.objects.bulk_create(
                [
                    MsrcMap(
                        month=month, kb=kb, cves=list(cves.values()), fetched_at=now
                    )
                    for kb, cves in kbs.items()
                ]
                # kb "" marks the month as fetched, also when it lists no KB
                + [MsrcMap(month=month, kb="", fetched_at=now)],
                batch_size=1000,
            )


def _msrc_map(kbs: set[str]) -> dict[str, dict[str, dict]]:
    """kb digits -> {cve: details}, for the KBs MSRC lists."""
    if not kbs:
        return {}
    _msrc_refresh()
    found: dict[str, dict[str, dict]] = defaultdict(dict)
    for kb, cves in MsrcMap.objects.filter(kb__in=kbs).values_list("kb", "cves"):
        for c in cves if isinstance(cves, list) else []:
            if isinstance(c, dict) and isinstance(c.get("id"), str):
                found[kb][c["id"]] = c
    return found


def _nvd_key() -> str:
    token = CoreSettings.objects.values_list("nvd_api_key", flat=True).first()
    if not token:
        return ""
    try:
        return decrypt_secret(token, NVD_KEY_INFO)
    except Exception:
        DebugLog.error("The NVD api key cannot be decrypted, enter it again.")
        return ""


def _nvd_lookups(cpes: set[str], prune: bool) -> dict[str, list[dict]]:
    """NVD answers per CPE name, cached for NVD_TTL. Absent when not checked."""
    cutoff = djangotime.now() - NVD_TTL
    found = dict(
        NvdLookup.objects.filter(cpe__in=cpes, fetched_at__gte=cutoff).values_list(
            "cpe", "result"
        )
    )
    missing = sorted(cpes - found.keys())[:NVD_MAX_PER_RUN]
    client = feeds.Nvd(_nvd_key()) if missing else None
    for i, cpe in enumerate(missing):
        try:
            result = client.cves(cpe)
        except Exception as e:
            # rate limit or outage, the rest waits for the next run
            DebugLog.error(
                f"NVD lookup failed, {len(missing) - i} apps keep their findings: {e}"
            )
            break
        NvdLookup.objects.update_or_create(
            cpe=cpe, defaults={"result": result, "fetched_at": djangotime.now()}
        )
        found[cpe] = result

    if prune:
        NvdLookup.objects.filter(fetched_at__lt=cutoff).delete()
    return found


def _scan_apps(agents: list[Agent], inventories: dict, prune: bool) -> int:
    """Windows updates through MSRC, known apps through NVD."""
    kbs: dict[int, set[str]] = defaultdict(set)
    pending = WinUpdate.objects.filter(
        agent__in=[a for a in agents if a.plat == AgentPlat.WINDOWS], installed=False
    ).values_list("agent_id", "kb", "kb_article_ids")
    for agent_pk, kb, article_ids in pending:
        for value in (kb, *(article_ids or [])):
            if m := feeds.KB_RE.fullmatch(str(value or "").strip()):
                kbs[agent_pk].add(m[1])
    msrc = _msrc_map(set().union(*kbs.values()))

    apps, unmapped = {}, {}
    for agent in agents:
        # no inventory yet, the app findings stay as they are
        if isinstance(inventories.get(agent.pk), list):
            apps[agent.pk], unmapped[agent.pk] = cpe_map.match(inventories[agent.pk])
    nvd = _nvd_lookups({cpe for found in apps.values() for *_, cpe in found}, prune)

    details: dict[str, dict] = {}
    plans = []
    for agent in agents:
        eco = PLAT_NAMES[agent.plat]
        from_msrc: dict[Key, str] = {}
        for kb in kbs.get(agent.pk, ()):
            package = f"Windows (KB{kb})"
            for cve, info in msrc.get(kb, {}).items():
                from_msrc[(package, "", cve)] = eco
                _detail(details, cve, info, f"{eco}|{package}", [f"KB{kb}"])

        from_nvd: dict[Key, str] = {}
        unchecked = set()
        for label, version, cpe in apps.get(agent.pk, ()):
            if cpe not in nvd:
                unchecked.add((label, version))
                continue
            for v in nvd[cpe]:
                from_nvd[(label, version, v["id"])] = eco
                _detail(details, v["id"], v, f"{eco}|{label}", v["fixed"])
        plans.append((agent, eco, from_msrc, from_nvd, unchecked))

    advisories = _merge_advisories(details)
    for agent, eco, from_msrc, from_nvd, unchecked in plans:
        try:
            with transaction.atomic():
                new = []
                if agent.plat == AgentPlat.WINDOWS:
                    new += _record(agent, Source.MSRC, from_msrc, advisories, set())
                if agent.pk in apps:
                    new += _record(agent, Source.NVD, from_nvd, advisories, unchecked)
                AgentScan.objects.update_or_create(
                    agent=agent,
                    defaults={
                        "ecosystem": eco,
                        "scanned_at": djangotime.now(),
                        "packages": len(apps.get(agent.pk, ()))
                        + len(kbs.get(agent.pk, ())),
                        "unchecked": len(unchecked),
                        "unmapped": unmapped.get(agent.pk, 0),
                    },
                )
        except Exception as e:
            DebugLog.error(
                agent=agent,
                message=f"Vulnerability import on {agent.hostname} failed: {e}",
            )
            continue
        _notify_new(agent, new)
    return len(plans)


def _vuxml_fixed(ranges) -> list[str]:
    """The "<" bounds of the affected ranges, lowest first. A range that ends
    with "<=" has no known fix."""
    found = {
        m[1]
        for r in (ranges if isinstance(ranges, list) else [])
        if isinstance(r, str) and (m := VUXML_FIX_RE.search(r))
    }
    return sorted(found, key=lambda v: (version_key(v) or (), v))


def import_pkg_audit(agent: Agent, audit: dict) -> None:
    """Findings from the pkg audit of a FreeBSD device; audit is package name
    -> {"version", "issues"}, as winupdate.posix parses it."""
    current: dict[Key, str] = {}
    details: dict[str, dict] = {}
    unchecked: set[tuple[str, str]] = set()
    issues = 0
    for name, entry in audit.items():
        package, version = name[:255], entry["version"][:255]
        for issue in entry["issues"]:
            if not isinstance(issue, dict):
                continue
            m = VUXML_ID_RE.search(str(issue.get("url") or ""))
            if not m:
                continue
            issues += 1
            if issues > MAX_AUDIT_ISSUES:
                # its findings stay as they are
                unchecked.add((package, version))
                continue
            cve = issue.get("cve")
            cves = (
                [c for c in cve if isinstance(c, str)] if isinstance(cve, list) else []
            )
            summary = str(issue.get("description") or "")
            if cves:
                summary += f" ({', '.join(cves)})"
            current[(package, version, m[1])] = FREEBSD
            _detail(
                details,
                m[1],
                {"summary": summary[:500]},
                f"{FREEBSD}|{package}",
                _vuxml_fixed(issue.get("Affected versions")),
            )

    row = InstalledSoftware.latest_for(agent)
    software = row.software if row and isinstance(row.software, list) else []
    packages = sum(
        1 for i in software if isinstance(i, dict) and i.get("source") == "pkg"
    )
    if unchecked:
        DebugLog.warning(
            agent=agent,
            message=f"pkg audit on {agent.hostname} listed {issues} issues, "
            f"only the first {MAX_AUDIT_ISSUES} were imported",
        )
    with transaction.atomic():
        advisories = _merge_advisories(details)
        new = _record(agent, Source.VUXML, current, advisories, unchecked)
        AgentScan.objects.update_or_create(
            agent=agent,
            defaults={
                "ecosystem": FREEBSD,
                "scanned_at": djangotime.now(),
                "packages": packages,
                "unchecked": len(unchecked),
            },
        )
    _notify_new(agent, new)


def scan(agent_pks: list[int] | None = None) -> str:
    agents = Agent.objects.defer(*AGENT_DEFER).filter(plat__in=SCANNED)
    if agent_pks is not None:
        agents = agents.filter(pk__in=agent_pks)
    agents = list(agents)

    inventories = dict(
        InstalledSoftware.objects.filter(agent__in=agents)
        .order_by("id")
        .values_list("agent_id", "software")
    )

    targets = []
    for agent in agents:
        if agent.plat != AgentPlat.LINUX:
            continue
        eco, _ = osv.ecosystem(agent.plat, agent.operating_system)
        if not eco:
            continue
        packages = osv.packages(inventories.get(agent.pk), eco)
        if packages:
            targets.append((agent, eco, packages))
        else:
            # no inventory yet, findings stay as they are
            AgentScan.objects.update_or_create(
                agent=agent,
                defaults={
                    "ecosystem": eco,
                    "scanned_at": djangotime.now(),
                    "packages": 0,
                    "unchecked": 0,
                },
            )

    keys = {(eco, n, v) for _, eco, packages in targets for n, v in packages}
    lookups = _lookups(keys)
    vulns = {v["id"]: v["modified"] for result in lookups.values() for v in result}
    advisories = _advisories(vulns)

    for agent, eco, packages in targets:
        try:
            with transaction.atomic():
                new = _apply(agent, eco, packages, lookups, advisories)
        except Exception as e:
            DebugLog.error(
                agent=agent,
                message=f"Vulnerability import on {agent.hostname} failed: {e}",
            )
            continue
        _notify_new(agent, new)

    others = _scan_apps(
        [a for a in agents if a.plat in PLAT_NAMES], inventories, agent_pks is None
    )

    if agent_pks is None:
        Lookup.objects.filter(fetched_at__lt=djangotime.now() - LOOKUP_TTL).delete()
    return (
        f"Checked {len(targets)} agents, {len(keys)} package versions, "
        f"{len(vulns)} advisories, {others} Windows and macOS agents"
    )


@app.task(bind=True)
def scan_vulnerabilities_task(self, agent_pks: list[int] | None = None) -> str:
    with redis_lock("vulns-scan", self.app.oid) as acquired:
        if not acquired:
            return "Vulnerability scan already running"
        return scan(agent_pks)
