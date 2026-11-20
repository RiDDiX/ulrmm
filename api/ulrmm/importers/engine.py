# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Preview and import of a source's snapshot.

Nothing that exists is overwritten: clients and sites are matched by name,
custom fields by model and name, scripts by name and shell, users by user
name, everything else by name. Matched rows keep their values; only empty
custom field values and empty policy and alert template slots of clients and
sites are filled in. A policy this source created gets the checks and tasks
it still lacks (by description and name) once their scripts, custom fields
or checks are here; apart from that, running an import twice adds nothing.
Imported users only get a role this source created (ImportSource.created).

Objects point at each other by name in the snapshot and are resolved through
what this import created or matched. An object whose reference does not
resolve, or that this installation refuses, is left out with the reason."""

from collections import defaultdict

from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import transaction
from django.utils import timezone as djangotime

from accounts.models import Role, User
from alerts.models import AlertTemplate
from alerts.serializers import AlertTemplateSerializer
from automation.models import Policy
from automation.serializers import PolicySerializer
from clients.models import Client, Site
from core.models import CoreSettings, CustomField, GlobalKVStore, URLAction
from core.serializers import URLActionSerializer
from logs.models import AuditLog
from reporting.models import ReportDataQuery, ReportHTMLTemplate, ReportTemplate
from reporting.serializers import (
    ReportDataQuerySerializer,
    ReportHTMLTemplateSerializer,
    ReportTemplateSerializer,
)
from scripts.models import Script, ScriptSnippet
from ulrmm.constants import AuditActionType, AuditObjType

from . import build, link
from .models import ImportedDevice

PARTS = (
    "clients",
    "custom_fields",
    "scripts",
    "snippets",
    "keystore",
    "url_actions",
    "alert_templates",
    "policies",
    "roles",
    "users",
    "reports",
    "devices",
)
# names listed per part in the preview
SHOWN = 200
USERS_NOTE = (
    "Users are created inactive without a password. An administrator activates "
    "each one and sets a password; second factors are set up again."
)
# a user whose role was not taken comes without one: no rights until assigned
NO_ROLE = "the role was not taken over, assign one before activating the user"
# a role of the same name here may grant more than the one over there
FOREIGN_ROLE = (
    "the role of that name here is not recorded as created by this source; "
    "check its rights and assign it by hand before activating the user"
)
LIMIT_LOST = (
    "it is limited to a client or site the source did not list, here it would "
    "see more"
)
BLOCK_LEFT_OUT = (
    "it blocks policy inheritance over there; the import does not change what "
    "is here, set it by hand"
)
REPEATED_SCRIPT = (
    "another script over there has the same name and shell; references to "
    "either cannot be told apart, rename one there and read the source again"
)
TEMPLATE_LOST = (
    "its alert template over there is not in the source's list or its name "
    "repeats there, set one here"
)
POLICY_SLOTS = ("server_policy", "workstation_policy")
EXCLUSION_LOST = (
    "it excludes a client or site the source did not list, so the import "
    "assigns it nowhere; assign it here by hand"
)


def _key(*names) -> tuple:
    return tuple(n.lower() for n in names)


def _existing():
    sites = {
        _key(client, site)
        for client, site in Site.objects.values_list("client__name", "name")
    }
    return {
        "clients": {_key(n) for n in Client.objects.values_list("name", flat=True)},
        "sites": sites,
        "custom_fields": {
            _key(m, n) for m, n in CustomField.objects.values_list("model", "name")
        },
        "scripts": {_key(n, s) for n, s in Script.objects.values_list("name", "shell")},
        "snippets": {
            _key(n) for n in ScriptSnippet.objects.values_list("name", flat=True)
        },
        "keystore": {
            _key(n) for n in GlobalKVStore.objects.values_list("name", flat=True)
        },
    }


def _site_names(snapshot) -> dict:
    # site ref -> (client name, site name)
    return {
        s["ref"]: (c["name"], s["name"])
        for c in snapshot.get("clients", [])
        for s in c["sites"]
        if s["ref"]
    }


def _part(names: list[str], new: list[str], skipped=(), left_out: int = 0) -> dict:
    """left_out: objects left out as a whole, neither new nor existing; the
    other skipped entries are parts of objects counted as usual."""
    skipped = list(skipped)
    return {
        "total": len(names),
        "new_count": len(new),
        "new": new[:SHOWN],
        "existing_count": len(names) - len(new) - left_out,
        "skipped_count": len(skipped),
        "skipped": skipped[:SHOWN],
    }


def _named(model, field: str = "name") -> set:
    return {_key(n) for n in model.objects.values_list(field, flat=True)}


def _sites_here() -> dict:
    return {
        _key(s.client.name, s.name): s for s in Site.objects.select_related("client")
    }


def _skip(name: str, reason: str) -> dict:
    return {"name": name, "reason": reason}


def _own(source, part: str) -> list[int]:
    return (source.created or {}).get(part, [])


def _remember(source, part: str, obj) -> None:
    # written in the part's transaction: a rolled back part forgets it in the
    # database; source.created keeps it, but the failed run ends right there
    source.created = {**(source.created or {}), part: [*_own(source, part), obj.pk]}
    type(source).objects.filter(pk=source.pk).update(created=source.created)


def _own_by_name(source, model, part: str) -> dict:
    return {o.name.lower(): o for o in model.objects.filter(pk__in=_own(source, part))}


def _listed(snap) -> tuple[set, set]:
    # the clients and sites of the snapshot; validate drops repeated names
    clients = snap.get("clients", [])
    return {_key(c["name"]) for c in clients}, {
        _key(c["name"], s["name"]) for c in clients for s in c["sites"]
    }


def _exclusion_lost(row, snap) -> bool:
    clients, sites = _listed(snap)
    return (
        any(k in row.get("lost", ()) for k in ("excluded_clients", "excluded_sites"))
        or any(_key(n) not in clients for n in row["excluded_clients"])
        or any(_key(c, s) not in sites for c, s in row["excluded_sites"])
    )


def _assignment(row) -> str:
    return f"{row['name']}: clients and sites"


def _blocked(snap) -> set:
    # templates with a lost exclusion reach no client or site, not even
    # through a policy
    return {
        t["name"].lower()
        for t in snap.get("alert_templates", [])
        if _exclusion_lost(t, snap)
    }


def _policy_template(p) -> str:
    return f"{p['name']}: alert template {p['alert_template']}"


class _Have:
    """What the snapshot would resolve against: the names here plus the
    names the import would add."""

    def __init__(self, snap):
        here = {_key(n, s) for n, s in Script.objects.values_list("name", "shell")}
        scripts = snap.get("scripts", [])
        left_out = _scripts_left_out(scripts, here)
        self.scripts = (here - build.repeated(scripts)) | {
            _key(s["name"], s["shell"])
            for i, s in enumerate(scripts)
            if i not in left_out
        }
        self.fields = {
            _key(n)
            for n in CustomField.objects.filter(model="agent").values_list(
                "name", flat=True
            )
        } | {
            _key(f["name"])
            for f in snap.get("custom_fields", [])
            if f["model"] == "agent"
        }
        self.clients = _named(Client) | {
            _key(c["name"]) for c in snap.get("clients", [])
        }
        self.sites = set(_sites_here()) | {
            _key(c["name"], s["name"])
            for c in snap.get("clients", [])
            for s in c["sites"]
        }
        self.hooks = _named(URLAction) | {
            _key(u["name"]) for u in snap.get("url_actions", [])
        }

    def script(self, ref) -> bool:
        return bool(ref) and _key(ref["name"], ref["shell"]) in self.scripts

    def owned(self, prefix: str, checks, tasks, present=()) -> list[dict]:
        """present: refs of checks that are here already"""
        skipped = []
        for row in checks:
            if why := build.missing(row, "checks", self.script):
                skipped.append(_skip(f"{prefix}{row['desc']}", why))
        refs = {
            c["ref"] for c in checks if not build.missing(c, "checks", self.script)
        } | set(present)
        for row in tasks:
            why = build.missing(row, "tasks", self.script)
            if not why and row["assigned_check"] and row["assigned_check"] not in refs:
                why = "its check was not imported"
            if (
                not why
                and row["custom_field"]
                and _key(row["custom_field"]) not in self.fields
            ):
                why = f"custom field {row['custom_field']} is not here"
            if why:
                skipped.append(_skip(f"{prefix}{row['name']}", why))
        return skipped


def _template_missing(t, have: _Have) -> str:
    for prefix in ("", "resolved_"):
        hook = t[f"{prefix}action_rest"]
        rest = t["fields"].get(f"{prefix}action_type") == "rest"
        if rest and hook and _key(hook) not in have.hooks:
            return f"URL action {hook} is not here"
        if not rest and t[f"{prefix}action"] and not have.script(t[f"{prefix}action"]):
            return f"script {t[f'{prefix}action']['name']} is not here"
    return ""


def _lost_actions(t) -> list[dict]:
    """Actions set over there whose script or URL action the source did not
    list; the template comes without them."""
    ret = []
    for prefix, shown in (("", "failure action"), ("resolved_", "resolved action")):
        rest = t["fields"].get(f"{prefix}action_type") == "rest"
        slot = f"{prefix}action_rest" if rest else f"{prefix}action"
        if slot in t.get("lost", ()):
            what = "URL action" if rest else "script"
            ret.append(
                _skip(
                    f"{t['name']}: {shown}",
                    f"its {what} is not in the source's list, set one here",
                )
            )
    return ret


def _role_missing(r, have: _Have) -> str:
    if r["superuser"]:
        return "a superuser role, give these rights here by hand"
    if r.get("lost"):
        return LIMIT_LOST
    for name in r["clients"]:
        if _key(name) not in have.clients:
            return f"client {name} is not here"
    for c, s in r["sites"]:
        if _key(c, s) not in have.sites:
            return f"site {c} / {s} is not here"
    return ""


# snapshot key, model, serializer and shown name of the reporting rows
REPORTS = (
    ("report_html", ReportHTMLTemplate, ReportHTMLTemplateSerializer, "HTML template"),
    ("report_queries", ReportDataQuery, ReportDataQuerySerializer, "Data query"),
    ("report_templates", ReportTemplate, ReportTemplateSerializer, "Report"),
)


def _report_rows(snap) -> list[tuple]:
    # (shown name, model, row)
    return [
        (f"{shown}: {r['name']}", model, r)
        for rows, model, _, shown in REPORTS
        for r in snap.get(rows, [])
    ]


def _plan_more(source, snap) -> dict:
    have = _Have(snap)
    actions = snap.get("url_actions", [])
    templates = snap.get("alert_templates", [])
    policies = snap.get("policies", [])
    roles = snap.get("roles", [])
    users = snap.get("users", [])
    hooks_here, templates_here = _named(URLAction), _named(AlertTemplate)
    policies_here, roles_here = _named(Policy), _named(Role)
    users_here = _named(User, "username")
    # the roles imported users would get: new ones and those it created before
    role_names = {
        _key(r["name"])
        for r in roles
        if _key(r["name"]) not in roles_here and not _role_missing(r, have)
    } | {_key(n) for n in _own_by_name(source, Role, "roles")}
    templates_left_out = {
        _key(t["name"])
        for t in templates
        if _key(t["name"]) not in templates_here and _template_missing(t, have)
    }

    def new(rows, here, field="name", missing=lambda r: ""):
        return [r[field] for r in rows if _key(r[field]) not in here and not missing(r)]

    t_skip = [
        _skip(t["name"], why)
        for t in templates
        if _key(t["name"]) not in templates_here and (why := _template_missing(t, have))
    ]
    t_left_out = len(t_skip)
    t_skip += [
        lost
        for t in templates
        if _key(t["name"]) not in templates_here and not _template_missing(t, have)
        for lost in _lost_actions(t)
    ]
    t_skip += [
        _skip(_assignment(t), EXCLUSION_LOST)
        for t in templates
        if _exclusion_lost(t, snap) and _key(t["name"]) not in templates_left_out
    ] + _slots_lost(snap, ("alert_template",))
    p_skip, to_complete = [], []
    own_policies = _own_by_name(source, Policy, "policies")
    blocked = {_key(n) for n in _blocked(snap)}
    template_names = (
        templates_here | ({_key(t["name"]) for t in templates} - templates_left_out)
    ) - blocked
    for p in policies:
        prefix = f"{p['name']}: "
        slot_empty = True
        if _key(p["name"]) not in policies_here:
            p_skip += have.owned(prefix, p["checks"], p["tasks"])
        elif policy := own_policies.get(p["name"].lower()):
            checks, tasks, present = _still_missing(policy, p)
            skipped = have.owned(prefix, checks, tasks, present)
            slot_empty = policy.alert_template_id is None
            template = (
                p["alert_template"]
                and slot_empty
                and _key(p["alert_template"]) in template_names
            )
            if template or len(checks) + len(tasks) > len(skipped):
                to_complete.append(p["name"])
            p_skip += skipped
        else:
            slot_empty = False
        if slot_empty and _key(p["alert_template"]) in blocked:
            p_skip.append(_skip(_policy_template(p), EXCLUSION_LOST))
        if slot_empty and "alert_template" in p["lost"]:
            p_skip.append(_skip(f"{p['name']}: alert template", TEMPLATE_LOST))
        if _exclusion_lost(p, snap):
            p_skip.append(_skip(_assignment(p), EXCLUSION_LOST))
    p_skip += _slots_lost(snap, POLICY_SLOTS)
    r_skip = [
        _skip(r["name"], why)
        for r in roles
        if _key(r["name"]) not in roles_here and (why := _role_missing(r, have))
    ]
    u_skip = [
        _skip(
            f"{u['username']}: role {u['role']}",
            FOREIGN_ROLE if _key(u["role"]) in roles_here else NO_ROLE,
        )
        for u in users
        if _key(u["username"]) not in users_here
        and u["role"]
        and _key(u["role"]) not in role_names
    ]
    reports = _report_rows(snap)
    report_names = {
        model: _named(model)
        for model in (ReportHTMLTemplate, ReportDataQuery, ReportTemplate)
    }
    html_names = report_names[ReportHTMLTemplate] | {
        _key(r["name"]) for r in snap.get("report_html", [])
    }
    rep_skip = [
        _skip(shown, f"HTML template {row['template_html']} is not here")
        for shown, model, row in reports
        if model is ReportTemplate
        and _key(row["name"]) not in report_names[model]
        and row["template_html"]
        and _key(row["template_html"]) not in html_names
    ]
    return {
        "url_actions": _part([a["name"] for a in actions], new(actions, hooks_here)),
        "alert_templates": _part(
            [t["name"] for t in templates],
            new(
                templates, templates_here, missing=lambda t: _template_missing(t, have)
            ),
            t_skip,
            t_left_out,
        ),
        "policies": {
            **_part(
                [p["name"] for p in policies], new(policies, policies_here), p_skip
            ),
            # created by this source earlier, now gets what it still lacked
            "to_complete_count": len(to_complete),
            "to_complete": to_complete[:SHOWN],
        },
        "roles": {
            **_part(
                [r["name"] for r in roles],
                new(roles, roles_here, missing=lambda r: _role_missing(r, have)),
                r_skip,
                len(r_skip),
            ),
            "unknown_permissions": sum(r["unknown"] for r in roles),
        },
        "users": {
            **_part(
                [u["username"] for u in users],
                new(users, users_here, "username"),
                u_skip,
            ),
            "note": USERS_NOTE,
        },
        "reports": _part(
            [shown for shown, _, _ in reports],
            [
                shown
                for shown, model, row in reports
                if _key(row["name"]) not in report_names[model]
                and not any(s["name"] == shown for s in rep_skip)
            ],
            rep_skip,
            len(rep_skip),
        ),
    }


def plan(source) -> dict:
    snap, have = source.snapshot or {}, _existing()
    clients = snap.get("clients", [])
    sites = [(c["name"], s["name"]) for c in clients for s in c["sites"]]
    fields = snap.get("custom_fields", [])
    scripts = snap.get("scripts", [])
    snippets = snap.get("snippets", [])
    keystore = snap.get("keystore", [])
    devices = snap.get("devices", [])
    known = set(source.devices.values_list("ref", flat=True))
    site_names = _site_names(snap)
    resolve = _Have(snap)
    scripts_left_out = _scripts_left_out(scripts, have["scripts"])
    keystore_left_out = [
        k
        for k in keystore
        if k.get("too_long") and _key(k["name"]) not in have["keystore"]
    ]
    return {
        "clients": _part(
            [c["name"] for c in clients],
            [c["name"] for c in clients if _key(c["name"]) not in have["clients"]],
            _blocks_left_out(snap) + _values_left_out(snap),
        ),
        "sites": _part(
            [f"{c} / {s}" for c, s in sites],
            [f"{c} / {s}" for c, s in sites if _key(c, s) not in have["sites"]],
        ),
        "custom_fields": _part(
            [f"{f['model']}: {f['name']}" for f in fields],
            [
                f"{f['model']}: {f['name']}"
                for f in fields
                if _key(f["model"], f["name"]) not in have["custom_fields"]
            ],
        ),
        "scripts": _part(
            [s["name"] for s in scripts],
            [
                s["name"]
                for i, s in enumerate(scripts)
                if _key(s["name"], s["shell"]) not in have["scripts"]
                and i not in scripts_left_out
            ],
            [_skip(scripts[i]["name"], why) for i, why in scripts_left_out.items()],
            len(scripts_left_out),
        ),
        "snippets": _part(
            [s["name"] for s in snippets],
            [s["name"] for s in snippets if _key(s["name"]) not in have["snippets"]],
        ),
        "keystore": _part(
            [k["name"] for k in keystore],
            [
                k["name"]
                for k in keystore
                if _key(k["name"]) not in have["keystore"] and not k.get("too_long")
            ],
            [_skip(k["name"], build.TOO_LONG) for k in keystore_left_out],
            len(keystore_left_out),
        ),
        "devices": {
            **_part(
                [d["hostname"] for d in devices],
                [d["hostname"] for d in devices if d["ref"] not in known],
                [
                    skip
                    for d in devices
                    if d["ref"] not in known
                    for skip in resolve.owned(
                        f"{d['hostname']}: ", d.get("checks", []), d.get("tasks", [])
                    )
                    + [
                        _skip(f"{d['hostname']}: {name}", build.TOO_LONG)
                        for name in d.get("too_long", [])
                    ]
                ],
            ),
            # devices whose site is not in the snapshot cannot be placed
            "without_site": sum(1 for d in devices if d["site_ref"] not in site_names),
            # policy, patch policy, settings, checks or tasks of their own
            "with_device_data": sum(1 for d in devices if _device_data(d)),
        },
        **_plan_more(source, snap),
    }


def _client_rows(snap) -> list[tuple]:
    # (shown name, key, row) of the clients and sites
    return [(c["name"], _key(c["name"]), c) for c in snap.get("clients", [])] + [
        (f"{c['name']} / {s['name']}", _key(c["name"], s["name"]), s)
        for c in snap.get("clients", [])
        for s in c["sites"]
    ]


def _blocks_left_out(snap) -> list[dict]:
    """Clients and sites here that do not block policy inheritance while they
    do over there; the import never changes what exists."""
    here = {_key(c.name): c.block_policy_inheritance for c in Client.objects.all()}
    here |= {k: s.block_policy_inheritance for k, s in _sites_here().items()}
    return [
        _skip(f"{name}: block policy inheritance", BLOCK_LEFT_OUT)
        for name, key, row in _client_rows(snap)
        if row["block_policy_inheritance"] and here.get(key) is False
    ]


def _values_left_out(snap) -> list[dict]:
    """Custom field values of clients and sites over the import's caps."""
    return [
        _skip(f"{name}: {value}", build.TOO_LONG)
        for name, _, row in _client_rows(snap)
        for value in row.get("too_long", ())
    ]


def _slots_lost(snap, slots: tuple) -> list[dict]:
    """The lost slots of clients and sites that are still empty here."""
    here = {_key(c.name): c for c in Client.objects.all()} | _sites_here()
    return [
        _skip(
            f"{name}: {slot.replace('_', ' ')}",
            TEMPLATE_LOST if slot == "alert_template" else build.POLICY_LOST,
        )
        for name, key, row in _client_rows(snap)
        for slot in slots
        if slot in row.get("lost", ())
        and getattr(here.get(key), f"{slot}_id", None) is None
    ]


def _import_clients(snap, done, skip):
    for row in _blocks_left_out(snap) + _values_left_out(snap):
        skip(row["name"], row["reason"])
    clients = {c.name.lower(): c for c in Client.objects.all()}
    for c in snap.get("clients", []):
        client = clients.get(c["name"].lower())
        if client is None:
            client = Client(
                name=c["name"], block_policy_inheritance=c["block_policy_inheritance"]
            )
            client.save()
            clients[client.name.lower()] = client
            done["clients"] += 1
        link.fill(client, "client", c["custom_fields"])
        sites = {s.name.lower(): s for s in client.sites.all()}
        for s in c["sites"]:
            site = sites.get(s["name"].lower())
            if site is None:
                site = Site(
                    client=client,
                    name=s["name"],
                    block_policy_inheritance=s["block_policy_inheritance"],
                )
                site.save()
                done["sites"] += 1
            link.fill(site, "site", s["custom_fields"])


def _import_fields(snap, done):
    have = {_key(m, n) for m, n in CustomField.objects.values_list("model", "name")}
    for f in snap.get("custom_fields", []):
        if _key(f["model"], f["name"]) in have:
            continue
        CustomField(
            model=f["model"], name=f["name"], type=f["type"], options=f["options"]
        ).save()
        have.add(_key(f["model"], f["name"]))
        done["custom_fields"] += 1


def _scripts_left_out(scripts, have: set) -> dict:
    """{index: reason} of the snapshot scripts the import leaves out; one
    that exists here and does not repeat there counts as existing. Every
    copy of a repeated name is left out, even with one of that name here:
    once one is renamed there, the other must not find a twin here."""
    twins = build.repeated(scripts)
    ret = {}
    for i, s in enumerate(scripts):
        key = _key(s["name"], s["shell"])
        if key in twins:
            ret[i] = REPEATED_SCRIPT
        elif key not in have and s.get("too_long"):
            ret[i] = build.TOO_LONG
    return ret


def _import_scripts(snap, done, skip):
    have = {_key(n, s) for n, s in Script.objects.values_list("name", "shell")}
    left_out = _scripts_left_out(snap.get("scripts", []), have)
    for i, s in enumerate(snap.get("scripts", [])):
        if i in left_out:
            skip(s["name"], left_out[i])
            continue
        if _key(s["name"], s["shell"]) in have:
            continue
        Script(
            name=s["name"],
            description=s["description"],
            shell=s["shell"],
            category=s["category"] or None,
            args=s["args"],
            env_vars=s["env_vars"],
            script_body=s["body"],
            default_timeout=s["timeout"],
            supported_platforms=s["platforms"],
            run_as_user=s["run_as_user"],
            syntax=s["syntax"] or None,
        ).save()
        have.add(_key(s["name"], s["shell"]))
        done["scripts"] += 1


def _import_snippets(snap, done):
    have = {_key(n) for n in ScriptSnippet.objects.values_list("name", flat=True)}
    for s in snap.get("snippets", []):
        if _key(s["name"]) in have:
            continue
        ScriptSnippet(
            name=s["name"], desc=s["desc"], code=s["code"], shell=s["shell"]
        ).save()
        have.add(_key(s["name"]))
        done["snippets"] += 1


def _import_keystore(snap, done, skip):
    have = {_key(n) for n in GlobalKVStore.objects.values_list("name", flat=True)}
    for k in snap.get("keystore", []):
        if _key(k["name"]) in have:
            continue
        if k.get("too_long"):
            skip(k["name"], build.TOO_LONG)
            continue
        GlobalKVStore(name=k["name"], value=k["value"]).save()
        have.add(_key(k["name"]))
        done["keystore"] += 1


DEVICE_KEYS = link.DEVICE_KEYS


def _device_data(d) -> dict:
    return {k: d[k] for k in DEVICE_KEYS if d.get(k)}


def _import_devices(source, snap, done, skip):
    site_names = _site_names(snap)
    sites = _sites_here()
    old = dict(source.devices.values_list("ref", "data"))
    for d in snap.get("devices", []):
        names = site_names.get(d["site_ref"])
        site = sites.get(_key(*names)) if names else None
        data = {
            "description": d["description"],
            "notes": d["notes"],
            "custom_fields": d["custom_fields"],
            **_device_data(d),
        }
        # what the link step left out stays listed
        if "link_skipped" in (old.get(d["ref"]) or {}):
            data["link_skipped"] = old[d["ref"]]["link_skipped"]
        _, created = ImportedDevice.objects.update_or_create(
            source=source,
            ref=d["ref"],
            defaults={
                "site": site,
                "hostname": d["hostname"],
                "serial": d["serial"],
                "plat": d["plat"],
                "goarch": d["goarch"],
                "monitoring_type": d["monitoring_type"],
                "os_name": d["os_name"],
                "data": data,
            },
        )
        done["devices"] += int(created)


def _by_name(model, field: str = "name") -> dict:
    # the oldest row wins when names repeat
    return {getattr(o, field).lower(): o for o in model.objects.order_by("-pk")}


def _pks(keys, rows: dict) -> list[int]:
    return [rows[k].pk for k in keys if k in rows]


def _client_pks(names, clients: dict) -> list[int]:
    return _pks((n.lower() for n in names), clients)


def _site_pks(pairs, sites: dict) -> list[int]:
    return _pks((_key(c, s) for c, s in pairs), sites)


def _unplaced(row, clients: dict, sites: dict, snap) -> str:
    """Why a new policy or template waits: an excluded client or site of the
    snapshot that is not here yet; created without it, it would apply there.
    Another name never comes, see _exclusion_lost."""
    listed_clients, listed_sites = _listed(snap)
    lost = [
        n
        for n in row["excluded_clients"]
        if n.lower() not in clients and _key(n) in listed_clients
    ] + [
        f"{c} / {s}"
        for c, s in row["excluded_sites"]
        if _key(c, s) not in sites and _key(c, s) in listed_sites
    ]
    return f"it excludes {lost[0]}, which is not here yet" if lost else ""


def _import_url_actions(snap, done, skip):
    have = _named(URLAction)
    for u in snap.get("url_actions", []):
        if _key(u["name"]) in have:
            continue
        action, why = build.save(URLActionSerializer(data=u))
        if action is None:
            skip(u["name"], why)
            continue
        have.add(_key(u["name"]))
        done["url_actions"] += 1


def _fill_slots(snap, slots: tuple, rows: dict) -> None:
    """Gives clients and sites here the policy or template they had over
    there, where that slot is still empty."""
    clients, sites = _by_name(Client), _sites_here()
    for c in snap.get("clients", []):
        pairs = [(clients.get(c["name"].lower()), c)] + [
            (sites.get(_key(c["name"], s["name"])), s) for s in c["sites"]
        ]
        for obj, row in pairs:
            if obj is None:
                continue
            changed = False
            for slot in slots:
                found = rows.get((row.get(slot) or "").lower())
                if found and getattr(obj, f"{slot}_id") is None:
                    setattr(obj, slot, found)
                    changed = True
            if changed:
                obj.save()


def _import_templates(source, snap, done, skip):
    templates, refs = _by_name(AlertTemplate), build.Refs(snap.get("scripts", []))
    hooks = _by_name(URLAction)
    clients, sites = _by_name(Client), _sites_here()
    for t in snap.get("alert_templates", []):
        if t["name"].lower() in templates:
            continue
        data = {**t["fields"], "name": t["name"]}
        why = ""
        for prefix in ("", "resolved_"):
            script, hook = t[f"{prefix}action"], t[f"{prefix}action_rest"]
            rest = t["fields"].get(f"{prefix}action_type") == "rest"
            data[f"{prefix}action"] = refs.script(script)
            data[f"{prefix}action_rest"] = (
                hooks[hook.lower()].pk if hook.lower() in hooks else None
            )
            if rest and hook and data[f"{prefix}action_rest"] is None:
                why = f"URL action {hook} is not here"
            elif not rest and script and data[f"{prefix}action"] is None:
                why = f"script {script['name']} is not here"
        why = why or _unplaced(t, clients, sites, snap)
        if why:
            skip(t["name"], why)
            continue
        data["excluded_clients"] = _client_pks(t["excluded_clients"], clients)
        data["excluded_sites"] = _site_pks(t["excluded_sites"], sites)
        template, why = build.save(AlertTemplateSerializer(data=data))
        if template is None:
            skip(t["name"], why)
            continue
        templates[t["name"].lower()] = template
        done["alert_templates"] += 1
        for lost in _lost_actions(t):
            skip(lost["name"], lost["reason"])
    for t in snap.get("alert_templates", []):
        if _exclusion_lost(t, snap) and templates.pop(t["name"].lower(), None):
            skip(_assignment(t), EXCLUSION_LOST)
    for lost in _slots_lost(snap, ("alert_template",)):
        skip(lost["name"], lost["reason"])
    _fill_slots(snap, ("alert_template",), templates)
    default = next((t for t in snap.get("alert_templates", []) if t["default"]), None)
    core = CoreSettings.objects.first()
    if default and core and core.alert_template_id is None:
        if found := templates.get(default["name"].lower()):
            core.alert_template = found
            core.save()


def _import_policies(source, snap, done, skip):
    policies, templates = _by_name(Policy), _by_name(AlertTemplate)
    refs = build.Refs(snap.get("scripts", []))
    clients, sites = _by_name(Client), _sites_here()
    own = _own_by_name(source, Policy, "policies")
    blocked = _blocked(snap)
    for p in snap.get("policies", []):
        prefix = f"{p['name']}: "
        if p["name"].lower() in policies:
            # never one this source did not create
            if policy := own.get(p["name"].lower()):
                completed = _complete(policy, p, templates, blocked, refs, skip)
                done["completed"]["policies"] += int(completed)
            continue
        if why := _unplaced(p, clients, sites, snap):
            skip(p["name"], why)
            continue
        template = None
        if "alert_template" in p["lost"]:
            skip(f"{p['name']}: alert template", TEMPLATE_LOST)
        elif p["alert_template"].lower() in blocked:
            skip(_policy_template(p), EXCLUSION_LOST)
        elif p["alert_template"]:
            template = templates.get(p["alert_template"].lower())
            if template is None:
                skip(_policy_template(p), "it is not here")
        data = {
            "name": p["name"],
            "desc": p["desc"],
            "active": p["active"],
            "enforced": p["enforced"],
            "alert_template": template.pk if template else None,
            "excluded_clients": _client_pks(p["excluded_clients"], clients),
            "excluded_sites": _site_pks(p["excluded_sites"], sites),
        }
        policy, why = build.save(PolicySerializer(data=data))
        if policy is None:
            skip(p["name"], why)
            continue
        policies[p["name"].lower()] = policy
        _remember(source, "policies", policy)
        done["policies"] += 1
        owner = {"policy": policy.pk}
        made = build.checks(owner, p["checks"], refs, skip, prefix)
        build.tasks(owner, p["tasks"], refs, made, skip, prefix)
        if p["patch_policy"]:
            build.patch_policy(
                p["patch_policy"], skip, f"{prefix}patch policy", policy=policy
            )
    for p in snap.get("policies", []):
        if _exclusion_lost(p, snap) and policies.pop(p["name"].lower(), None):
            skip(_assignment(p), EXCLUSION_LOST)
    for lost in _slots_lost(snap, POLICY_SLOTS):
        skip(lost["name"], lost["reason"])
    _fill_slots(snap, POLICY_SLOTS, policies)


def _still_missing(policy, p) -> tuple[list, list, dict]:
    checks, tasks, present = build.missing_children(
        policy.policychecks, policy.autotasks, p
    )
    # listed when the policy was created; never one to add later
    return checks, [t for t in tasks if not build.ran_once(t)], present


def _complete(policy, p, templates, blocked, refs, skip) -> bool:
    """Adds what a policy this source created still lacks: its checks, its
    tasks and an empty alert template slot. Returns whether it added any."""
    prefix = f"{p['name']}: "
    checks, tasks, present = _still_missing(policy, p)
    owner = {"policy": policy.pk}
    new = build.checks(owner, checks, refs, skip, prefix)
    added = bool(new) | bool(
        build.tasks(owner, tasks, refs, {**present, **new}, skip, prefix)
    )
    template = templates.get(p["alert_template"].lower())
    if policy.alert_template_id is None and "alert_template" in p["lost"]:
        skip(f"{p['name']}: alert template", TEMPLATE_LOST)
    elif policy.alert_template_id is None and p["alert_template"].lower() in blocked:
        skip(_policy_template(p), EXCLUSION_LOST)
    elif template and policy.alert_template_id is None:
        policy.alert_template = template
        policy.save()
        added = True
    return added


def _import_roles(source, snap, done, skip):
    from accounts.serializers import RoleSerializer

    have, clients, sites = _named(Role), _by_name(Client), _sites_here()
    for r in snap.get("roles", []):
        if _key(r["name"]) in have:
            continue
        why = (
            "a superuser role, give these rights here by hand" if r["superuser"] else ""
        )
        if not why and r.get("lost"):
            why = LIMIT_LOST
        # a restriction that does not resolve would let the role see more
        lost = [n for n in r["clients"] if n.lower() not in clients] + [
            f"{c} / {s}" for c, s in r["sites"] if _key(c, s) not in sites
        ]
        if not why and lost:
            why = f"{lost[0]} is not here"
        if why:
            skip(r["name"], why)
            continue
        data = {
            "name": r["name"],
            **r["perms"],
            "can_view_clients": _client_pks(r["clients"], clients),
            "can_view_sites": _site_pks(r["sites"], sites),
        }
        role, why = build.save(RoleSerializer(data=data))
        if role is None:
            skip(r["name"], why)
            continue
        have.add(_key(r["name"]))
        _remember(source, "roles", role)
        done["roles"] += 1


def _import_users(source, snap, done, skip):
    have, roles = _named(User, "username"), _own_by_name(source, Role, "roles")
    roles_here = _named(Role)
    for u in snap.get("users", []):
        if _key(u["username"]) in have:
            continue
        role = roles.get(u["role"].lower()) if u["role"] else None
        # passwords and second factors never come along, see USERS_NOTE
        user = User(
            username=u["username"],
            email=u["email"],
            first_name=u["first_name"],
            last_name=u["last_name"],
            role=role,
            is_active=False,
        )
        user.set_unusable_password()
        try:
            user.full_clean(exclude=["password"])
        except DjangoValidationError as e:
            skip(u["username"], build.reason(e.message_dict))
            continue
        with transaction.atomic():
            user.save()
        if u["role"] and role is None:
            why = FOREIGN_ROLE if _key(u["role"]) in roles_here else NO_ROLE
            skip(f"{u['username']}: role {u['role']}", why)
        have.add(_key(u["username"]))
        done["users"] += 1


def _import_reports(snap, done, skip):
    html = _by_name(ReportHTMLTemplate)
    for rows, model, serializer, kind in REPORTS:
        have = _named(model)
        for row in snap.get(rows, []):
            shown = f"{kind}: {row['name']}"
            if _key(row["name"]) in have:
                continue
            data = dict(row)
            if model is ReportTemplate:
                linked = html.get(row["template_html"].lower())
                if row["template_html"] and linked is None:
                    skip(shown, f"HTML template {row['template_html']} is not here")
                    continue
                data["template_html"] = linked.pk if linked else None
            obj, why = build.save(serializer(data=data))
            if obj is None:
                skip(shown, why)
                continue
            if model is ReportHTMLTemplate:
                html[obj.name.lower()] = obj
            have.add(_key(row["name"]))
            done["reports"] += 1


def run(source, parts, username: str = "importer") -> dict:
    """Imports the chosen parts of the snapshot, each part in a transaction
    of its own, and links the devices to agents that are already enrolled.
    Left out objects come back under "skipped" by part."""
    snap = source.snapshot or {}
    done = dict.fromkeys((*PARTS, "sites", "linked"), 0)
    # own policies a re-run added checks, tasks or the template to
    done["completed"] = {"policies": 0}
    skipped = defaultdict(list)
    steps = (
        # fields first: client, site and device values need them
        ("custom_fields", lambda skip: _import_fields(snap, done)),
        ("clients", lambda skip: _import_clients(snap, done, skip)),
        ("scripts", lambda skip: _import_scripts(snap, done, skip)),
        ("snippets", lambda skip: _import_snippets(snap, done)),
        ("keystore", lambda skip: _import_keystore(snap, done, skip)),
        ("url_actions", lambda skip: _import_url_actions(snap, done, skip)),
        ("alert_templates", lambda skip: _import_templates(source, snap, done, skip)),
        ("policies", lambda skip: _import_policies(source, snap, done, skip)),
        ("roles", lambda skip: _import_roles(source, snap, done, skip)),
        ("users", lambda skip: _import_users(source, snap, done, skip)),
        ("reports", lambda skip: _import_reports(snap, done, skip)),
        ("devices", lambda skip: _import_devices(source, snap, done, skip)),
    )
    committed, running = [], None
    try:
        for part, step in steps:
            if part not in parts:
                continue
            running = part
            with transaction.atomic():
                step(
                    lambda name, why, part=part: skipped[part].append(_skip(name, why))
                )
            committed.append(part)
        source.last_import = djangotime.now()
        type(source).objects.filter(pk=source.pk).update(last_import=source.last_import)
        if "devices" in parts:
            # after the devices part committed: its own step in the audit
            running = "linking"
            done["linked"] = link.link_source(source)
        running = None
    finally:
        # also after a failure: the parts before it are committed
        chosen = [p for p in PARTS if p in committed]
        message = f"{username} imported from {source.name}: {', '.join(chosen)}"
        added = {p: done[p] for p in chosen}
        if "clients" in committed:
            added["sites"] = done["sites"]
        AuditLog.objects.create(
            username=username,
            object_type=AuditObjType.BULK,
            action=AuditActionType.ADD,
            message=message[:255],
            after_value={
                "source": source.name,
                "parts": chosen,
                "added": added,
                "left_out": {p: len(skipped.get(p, ())) for p in chosen},
                "completed": done["completed"],
                **({"failed": running} if running else {}),
            },
        )
    done["skipped"] = {k: v[:SHOWN] for k, v in skipped.items()}
    done["skipped_total"] = {k: len(v) for k, v in skipped.items()}
    return done
