# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""The upstream server this project started from, through its REST API
with an API key (header X-API-KEY, a superuser's key reads everything).

Lists are bare JSON arrays without paging. The agent list names client and
site instead of giving their ids, so devices are placed by those names.
Script bodies need one request per script (GET /scripts/<id>/), a device's
policy, patch policy and settings one per device (GET /agents/<agent_id>/).
Checks and tasks come in one list each for policies and devices; other
objects point at them by numeric id, which is turned into names here. The
reporting endpoints are missing on servers without that module. A command
runs through POST /agents/<agent_id>/cmd/; with the agent unreachable the
server answers 200 "natsdown". DELETE /agents/<agent_id>/ uninstalls the
agent: 200 "<hostname> will now be uninstalled.", sent without waiting for
the device, and the row is gone at once."""

import re
from collections import defaultdict

from .base import TASK_FIELDS, NotFound, Source, SourceError

SHELLS = {"windows": "powershell", "linux": "/bin/bash", "darwin": "/bin/bash"}
# what the agent waits for the command; it only starts the detached installer
CMD_TIMEOUT = 60
# agent ids go into URL paths, a DELETE among them
AGENT_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,255}")


def _values(rows, names: dict) -> dict:
    # [{field: <id>, value}] -> {name: value}
    ret = {}
    for row in rows if isinstance(rows, list) else []:
        if isinstance(row, dict) and (name := names.get(row.get("field"))):
            ret[name] = row.get("value")
    return ret


def _ids(value) -> list:
    return value if isinstance(value, list) else []


class Upstream(Source):
    KIND = "upstream"
    SECRETS = ("api_key",)
    PUSH_PLATS = ("windows", "linux", "darwin")
    REMOVES = True
    PARTS = (
        *Source.PARTS,
        "url_actions",
        "alert_templates",
        "policies",
        "roles",
        "users",
        "reports",
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.session.headers["X-API-KEY"] = self.secrets.get("api_key", "")

    def _get(self, path: str, **params) -> list:
        data = self.call("GET", path, params=params or None)
        if data == [None]:
            # an empty list of the reporting module
            return []
        if not isinstance(data, list):
            raise SourceError(f"{path} gave an unexpected answer")
        return [d for d in data if isinstance(d, dict)]

    def fetch(self) -> dict:
        if not self.secrets.get("api_key"):
            raise SourceError("Enter the API key.")
        fields = self._get("/core/customfields/")
        names = {f.get("id"): f.get("name") for f in fields}

        clients, site_ids, found = [], {}, self._get("/clients/")
        for c in found:
            sites = []
            for s in c.get("sites") or []:
                if not isinstance(s, dict):
                    continue
                site_ids[(c.get("name"), s.get("name"))] = str(s.get("id"))
                sites.append(
                    {
                        "ref": str(s.get("id")),
                        "name": s.get("name"),
                        "custom_fields": _values(s.get("custom_fields"), names),
                    }
                )
            clients.append(
                {
                    "ref": str(c.get("id")),
                    "name": c.get("name"),
                    "custom_fields": _values(c.get("custom_fields"), names),
                    "sites": sites,
                }
            )

        notes = defaultdict(list)
        for n in self._get("/agents/notes/"):
            notes[n.get("agent_id")].append(n.get("note"))

        devices = [
            {
                "ref": a.get("agent_id"),
                "site_ref": site_ids.get(
                    (a.get("client_name"), a.get("site_name")), ""
                ),
                "hostname": a.get("hostname"),
                "serial": a.get("serial_number"),
                "plat": a.get("plat"),
                "goarch": a.get("goarch"),
                "monitoring_type": a.get("monitoring_type"),
                "os_name": a.get("operating_system"),
                "description": a.get("description"),
                "notes": notes.get(a.get("agent_id"), []),
                "custom_fields": _values(a.get("custom_fields"), names),
            }
            for a in self._get("/agents/", detail="true")
        ]

        scripts = []
        listed = self._get("/scripts/", showCommunityScripts="false")
        for s in listed:
            if s.get("script_type") != "userdefined":
                continue
            full = self.call("GET", f"/scripts/{int(s['id'])}/")
            if not isinstance(full, dict):
                continue
            scripts.append(
                {
                    "name": full.get("name"),
                    "description": full.get("description"),
                    "shell": full.get("shell"),
                    "category": full.get("category"),
                    "args": full.get("args"),
                    "env_vars": full.get("env_vars"),
                    "body": full.get("script_body"),
                    "timeout": full.get("default_timeout"),
                    "platforms": full.get("supported_platforms"),
                    "run_as_user": full.get("run_as_user"),
                    "syntax": full.get("syntax"),
                }
            )

        refs = {
            "scripts": {
                s.get("id"): {"name": s.get("name"), "shell": s.get("shell")}
                for s in listed
            },
            "fields": names,
            "clients": {c.get("id"): c.get("name") for c in found},
            "sites": {
                s.get("id"): [c.get("name"), s.get("name")]
                for c in found
                for s in c.get("sites") or []
                if isinstance(s, dict)
            },
            "agents": {
                a.get("id"): a.get("agent_id")
                for a in self._get("/agents/", detail="false")
            },
        }
        more, found_by = self._more(refs)
        self._assignments(clients, found, found_by)
        self._device_data(devices, refs, found_by)
        return {
            "clients": clients,
            "custom_fields": fields,
            "scripts": scripts,
            "snippets": self._get("/scripts/snippets/"),
            "keystore": self._get("/core/keystore/"),
            "devices": devices,
            **more,
        }

    def _optional(self, path: str) -> list:
        try:
            return self._get(path)
        except NotFound:
            return []

    def _check(self, row, refs) -> dict:
        return {
            "ref": str(row.get("id")),
            "desc": row.get("readable_desc"),
            "script": refs["scripts"].get(row.get("script")),
            "fields": row,
        }

    def _task(self, row, refs) -> dict:
        actions = []
        for a in row.get("actions") or []:
            if isinstance(a, dict) and a.get("type") == "script":
                a = {**a, "script": refs["scripts"].get(a.get("script"))}
            actions.append(a)
        check = row.get("assigned_check")
        return {
            "ref": str(row.get("id")),
            "fields": {k: row.get(k) for k in TASK_FIELDS},
            "actions": actions,
            "assigned_check": "" if check is None else str(check),
            "custom_field": refs["fields"].get(row.get("custom_field")),
        }

    def _sites(self, ids, refs) -> list:
        return [refs["sites"][i] for i in _ids(ids) if i in refs["sites"]]

    def _more(self, refs) -> dict:
        # device-level checks and tasks are the ones with an agent and no policy
        owned = {"policy": defaultdict(list), "agent": defaultdict(list)}
        checks = {}
        for c in self._get("/checks/"):
            if c.get("managed_by_policy"):
                continue
            owner = "policy" if c.get("policy") else "agent"
            checks[c.get("id")] = row = self._check(c, refs)
            owned[owner][c.get(owner)].append(("checks", row))
        for t in self._get("/tasks/"):
            if t.get("managed_by_policy"):
                continue
            owner = "policy" if t.get("policy") else "agent"
            owned[owner][t.get(owner)].append(("tasks", self._task(t, refs)))

        def split(rows) -> dict:
            ret = {"checks": [], "tasks": []}
            for kind, row in rows:
                ret[kind].append(row)
            return ret

        actions = self._get("/core/urlaction/")
        hooks = {u.get("id"): u.get("name") for u in actions}
        templates, template_names, excluded = [], {}, defaultdict(set)
        for t in self._get("/alerts/templates/"):
            template_names[t.get("id")] = t.get("name")
            for pk in _ids(t.get("excluded_agents")):
                excluded[("template", pk)].add(t.get("name"))
            slots = {
                "action": refs["scripts"].get(t.get("action")),
                "resolved_action": refs["scripts"].get(t.get("resolved_action")),
                "action_rest": hooks.get(t.get("action_rest")),
                "resolved_action_rest": hooks.get(t.get("resolved_action_rest")),
            }
            templates.append(
                {
                    "name": t.get("name"),
                    "default": t.get("default_template") is True,
                    "fields": t,
                    **slots,
                    # set over there, but not in the lists read (library scripts)
                    "lost": [k for k, v in slots.items() if t.get(k) and not v],
                    "excluded_clients": [
                        refs["clients"].get(i) for i in _ids(t.get("excluded_clients"))
                    ],
                    "excluded_sites": self._sites(t.get("excluded_sites"), refs),
                }
            )

        policies, policy_names = [], {}
        for p in self._get("/automation/policies/"):
            policy_names[p.get("id")] = p.get("name")
            for pk in _ids(p.get("excluded_agents")):
                excluded[("policy", pk)].add(p.get("name"))
            patch = [w for w in _ids(p.get("winupdatepolicy")) if isinstance(w, dict)]
            policies.append(
                {
                    "name": p.get("name"),
                    "desc": p.get("desc"),
                    "active": p.get("active"),
                    "enforced": p.get("enforced"),
                    # absent from the list when the policy has none
                    "alert_template": template_names.get(p.get("alert_template")),
                    "patch_policy": patch[0] if patch else None,
                    **split(owned["policy"].get(p.get("id"), [])),
                    "excluded_clients": [
                        refs["clients"].get(i) for i in _ids(p.get("excluded_clients"))
                    ],
                    "excluded_sites": self._sites(p.get("excluded_sites"), refs),
                }
            )

        roles = [
            {
                "name": r.get("name"),
                "fields": r,
                "clients": [
                    refs["clients"].get(i) for i in _ids(r.get("can_view_clients"))
                ],
                "sites": self._sites(r.get("can_view_sites"), refs),
            }
            for r in self._get("/accounts/roles/")
        ]
        role_names = {r["fields"].get("id"): r["name"] for r in roles}
        users = [
            {**u, "role": role_names.get(u.get("role"))}
            for u in self._get("/accounts/users/")
        ]

        html = self._optional("/reporting/htmltemplates/")
        html_names = {h.get("id"): h.get("name") for h in html}
        reports = [
            {**t, "template_html": html_names.get(t.get("template_html"))}
            for t in self._optional("/reporting/templates/")
        ]
        return {
            "url_actions": actions,
            "alert_templates": templates,
            "policies": policies,
            "roles": roles,
            "users": users,
            "report_html": html,
            "report_queries": self._optional("/reporting/dataqueries/"),
            "report_templates": reports,
        }, {
            "policies": policy_names,
            "templates": template_names,
            "agent": {k: split(v) for k, v in owned["agent"].items()},
            "excluded": excluded,
        }

    def _assignments(self, clients, found, by) -> None:
        # the policies and template a client or site has, by name
        def names(row) -> dict:
            return {
                "server_policy": by["policies"].get(row.get("server_policy")),
                "workstation_policy": by["policies"].get(row.get("workstation_policy")),
                "alert_template": by["templates"].get(row.get("alert_template")),
            }

        mine = {c["ref"]: c for c in clients}
        for c in found:
            client = mine.get(str(c.get("id")))
            if client is None:
                continue
            client.update(names(c))
            sites = {s["ref"]: s for s in client["sites"]}
            for s in c.get("sites") or []:
                if isinstance(s, dict) and (site := sites.get(str(s.get("id")))):
                    site.update(names(s))

    def _device_data(self, devices, refs, by) -> None:
        pks = {agent_id: pk for pk, agent_id in refs["agents"].items()}
        for d in devices:
            pk = pks.get(d["ref"])
            own = by["agent"].get(pk, {})
            d.update(
                checks=own.get("checks", []),
                tasks=own.get("tasks", []),
                excluded_policies=sorted(by["excluded"].get(("policy", pk), ())),
                excluded_templates=sorted(by["excluded"].get(("template", pk), ())),
            )
            try:
                detail = self.call("GET", f"/agents/{d['ref']}/")
            except NotFound:
                # removed over there since the list was read
                continue
            if not isinstance(detail, dict):
                continue
            patch = [
                w for w in _ids(detail.get("winupdatepolicy")) if isinstance(w, dict)
            ]
            d.update(
                policy=by["policies"].get(detail.get("policy")),
                patch_policy=patch[0] if patch else None,
                settings=detail,
            )

    def _agent(self, ref: str) -> str:
        if not AGENT_ID_RE.fullmatch(ref):
            raise SourceError("the device id has characters an agent id never has")
        return f"/agents/{ref}/"

    def device(self, ref: str) -> dict:
        detail = self.call("GET", self._agent(ref))
        if not isinstance(detail, dict):
            raise SourceError(f"{self._agent(ref)} gave an unexpected answer")
        return detail

    def remove(self, ref: str, hostname: str) -> None:
        answer = self.call("DELETE", self._agent(ref))
        if answer != f"{hostname} will now be uninstalled.":
            raise SourceError("the removal got an unexpected answer")

    def push(self, ref: str, plat: str, command: str, url: str = "") -> None:
        if plat not in SHELLS:
            raise SourceError(f"no shell for {plat}")
        answer = self.call(
            "POST",
            f"{self._agent(ref)}cmd/",
            json={
                "shell": SHELLS[plat],
                "cmd": command,
                "timeout": CMD_TIMEOUT,
                "run_as_user": False,
                "custom_shell": None,
            },
            timeout=CMD_TIMEOUT + 30,
        )
        if answer == "natsdown":
            raise SourceError("the agent is offline in the source")
