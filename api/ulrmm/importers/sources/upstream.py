# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""The upstream server this project started from, through its REST API
with an API key (header X-API-KEY, a superuser's key reads everything).

Lists are bare JSON arrays without paging. The agent list names client and
site instead of giving their ids, so devices are placed by those names.
Script bodies need one request per script (GET /scripts/<id>/). A command
runs through POST /agents/<agent_id>/cmd/; with the agent unreachable the
server answers 200 "natsdown"."""

from collections import defaultdict

from .base import Source, SourceError

SHELLS = {"windows": "powershell", "linux": "/bin/bash", "darwin": "/bin/bash"}
# what the agent waits for the command; it only starts the detached installer
CMD_TIMEOUT = 60


def _values(rows, names: dict) -> dict:
    # [{field: <id>, value}] -> {name: value}
    ret = {}
    for row in rows if isinstance(rows, list) else []:
        if isinstance(row, dict) and (name := names.get(row.get("field"))):
            ret[name] = row.get("value")
    return ret


class Upstream(Source):
    KIND = "upstream"
    SECRETS = ("api_key",)
    PUSH_PLATS = ("windows", "linux", "darwin")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.session.headers["X-API-KEY"] = self.secrets.get("api_key", "")

    def _get(self, path: str, **params) -> list:
        data = self.call("GET", path, params=params or None)
        if not isinstance(data, list):
            raise SourceError(f"{path} gave an unexpected answer")
        return [d for d in data if isinstance(d, dict)]

    def fetch(self) -> dict:
        if not self.secrets.get("api_key"):
            raise SourceError("Enter the API key.")
        fields = self._get("/core/customfields/")
        names = {f.get("id"): f.get("name") for f in fields}

        clients, site_ids = [], {}
        for c in self._get("/clients/"):
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

        return {
            "clients": clients,
            "custom_fields": fields,
            "scripts": scripts,
            "snippets": self._get("/scripts/snippets/"),
            "keystore": self._get("/core/keystore/"),
            "devices": devices,
        }

    def push(self, ref: str, plat: str, command: str, url: str = "") -> None:
        if plat not in SHELLS:
            raise SourceError(f"no shell for {plat}")
        answer = self.call(
            "POST",
            f"/agents/{ref}/cmd/",
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
