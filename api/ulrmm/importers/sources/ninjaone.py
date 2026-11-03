# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""NinjaOne through its public API v2 (OpenAPI spec 2.0.9-draft).

The address is the region host, e.g. https://eu.ninjarmm.com. An API app
with the client credentials grant and the scopes monitoring and management
gives the token (POST /ws/oauth/token). Organizations map to clients,
locations to sites, agent devices to devices; notes and custom field values
come along. The API exposes no script bodies, so scripts are not imported.

NinjaOne runs only scripts from its own library (POST
/v2/device/{id}/script/run with the script id), no free commands. To move
devices, create one library script per platform that downloads and runs
the link it gets as its parameter (the import page shows them) and enter
their ids as the options script_windows and script_linux."""

import datetime as dt

from .base import MAX_ITEMS, Source, SourceError

PAGE = 200
CLASSES = {
    "WINDOWS_WORKSTATION": ("windows", "workstation"),
    "WINDOWS_SERVER": ("windows", "server"),
    "MAC": ("darwin", "workstation"),
    "MAC_SERVER": ("darwin", "server"),
    "LINUX_WORKSTATION": ("linux", "workstation"),
    "LINUX_SERVER": ("linux", "server"),
}
TYPES = {
    "CHECKBOX": "checkbox",
    "DROPDOWN": "single",
    "MULTI_SELECT": "multiple",
    "DATE": "datetime",
    "DATE_TIME": "datetime",
    "NUMERIC": "number",
    "DECIMAL": "number",
}
SCOPES = {"NODE": "agent", "LOCATION": "site", "ORGANIZATION": "client"}
ARCH = {"64-bit": "amd64", "32-bit": "386", "ARM64": "arm64"}


def _value(value, kind: str):
    if kind == "datetime" and isinstance(value, (int, float)):
        # DATE values are epoch milliseconds
        with_tz = dt.datetime.fromtimestamp(value / 1000, tz=dt.timezone.utc)
        return with_tz.strftime("%Y-%m-%dT%H:%M")
    if kind == "multiple" and isinstance(value, str):
        return [v.strip() for v in value.split(",") if v.strip()]
    return value


class NinjaOne(Source):
    KIND = "ninjaone"
    SECRETS = ("client_secret",)
    PUSH_PLATS = ("windows", "linux")

    def _login(self) -> None:
        client_id = self.options.get("client_id", "")
        secret = self.secrets.get("client_secret", "")
        if not client_id or not secret:
            raise SourceError("Enter the client id and the client secret.")
        token = self.call(
            "POST",
            "/ws/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": secret,
                "scope": "monitoring management",
            },
        )
        if not isinstance(token, dict) or not token.get("access_token"):
            raise SourceError("the token endpoint gave no access token")
        self.session.headers["Authorization"] = f"Bearer {token['access_token']}"

    def _pages(self, path: str) -> list:
        ret, after = [], None
        while True:
            params = {"pageSize": PAGE, **({"after": after} if after else {})}
            page = self.call("GET", path, params=params)
            if not isinstance(page, list):
                raise SourceError(f"{path} gave an unexpected answer")
            page = [p for p in page if isinstance(p, dict)]
            ret += page
            if len(page) < PAGE or len(ret) > MAX_ITEMS:
                return ret
            after = page[-1].get("id")

    def _values(self, path: str, labels: dict, kinds: dict) -> dict:
        try:
            values = self.call("GET", path)
        except SourceError:
            # fields hidden from the API give nothing; values are optional
            return {}
        if not isinstance(values, dict):
            return {}
        return {
            labels.get(k, k): _value(v, kinds.get(k, "text")) for k, v in values.items()
        }

    def fetch(self) -> dict:
        self._login()
        definitions = self.call("GET", "/v2/device-custom-fields") or []
        fields, labels, kinds = [], {}, {}
        for d in definitions if isinstance(definitions, list) else []:
            if not isinstance(d, dict) or not d.get("name"):
                continue
            label = d.get("label") or d["name"]
            labels[d["name"]] = label
            kinds[d["name"]] = TYPES.get(d.get("type"), "text")
            for scope in d.get("definitionScope") or []:
                if scope in SCOPES:
                    fields.append(
                        {
                            "model": SCOPES[scope],
                            "name": label,
                            "type": kinds[d["name"]],
                        }
                    )

        clients = []
        for org in self._pages("/v2/organizations-detailed"):
            oid = org.get("id")
            if not isinstance(oid, int):
                continue
            sites = [
                {
                    "ref": str(loc.get("id")),
                    "name": loc.get("name"),
                    "custom_fields": self._values(
                        f"/v2/organization/{oid}/location/{int(loc['id'])}/custom-fields",
                        labels,
                        kinds,
                    ),
                }
                for loc in org.get("locations") or []
                if isinstance(loc, dict) and isinstance(loc.get("id"), int)
            ]
            clients.append(
                {
                    "ref": str(oid),
                    "name": org.get("name"),
                    "custom_fields": self._values(
                        f"/v2/organization/{oid}/custom-fields", labels, kinds
                    ),
                    "sites": sites,
                }
            )

        devices = []
        for d in self._pages("/v2/devices-detailed"):
            plat, mon = CLASSES.get(d.get("nodeClass"), ("", ""))
            if not plat or not isinstance(d.get("id"), int):
                continue
            system = d.get("system") if isinstance(d.get("system"), dict) else {}
            os_info = d.get("os") if isinstance(d.get("os"), dict) else {}
            devices.append(
                {
                    "ref": str(d["id"]),
                    "site_ref": str(d.get("locationId")),
                    "hostname": d.get("systemName") or d.get("dnsName"),
                    "serial": system.get("serialNumber")
                    or system.get("biosSerialNumber"),
                    "plat": plat,
                    "goarch": ARCH.get(os_info.get("architecture"), ""),
                    "monitoring_type": mon,
                    "os_name": os_info.get("name"),
                    "description": (
                        d.get("displayName")
                        if d.get("displayName") != d.get("systemName")
                        else ""
                    ),
                    "notes": [
                        n.get("text")
                        for n in d.get("notes") or []
                        if isinstance(n, dict)
                    ],
                    "custom_fields": self._values(
                        f"/v2/device/{d['id']}/custom-fields", labels, kinds
                    ),
                }
            )
        return {"clients": clients, "custom_fields": fields, "devices": devices}

    def push(self, ref: str, plat: str, command: str, url: str = "") -> None:
        script = self.options.get(f"script_{plat}", "")
        if not str(script).isdigit():
            raise SourceError(
                f"Enter the NinjaOne script id for {plat} (option script_{plat})."
            )
        if not url:
            raise SourceError(f"no installer link for {plat}")
        if not ref.isdigit():
            raise SourceError("not a NinjaOne device id")
        if "Authorization" not in self.session.headers:
            self._login()
        self.call(
            "POST",
            f"/v2/device/{ref}/script/run",
            json={"type": "SCRIPT", "id": int(script), "parameters": url},
        )
