# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Warranty lookup by serial number: Dell TechDirect, Lenovo (unofficial)."""

import datetime as dt
from contextlib import suppress
from urllib.parse import quote

import requests
from cryptography.fernet import InvalidToken
from django.utils import timezone as djangotime

from core.models import DELL_API_INFO
from core.utils import get_core_settings
from logs.models import DebugLog
from remote.utils import decrypt_secret

TIMEOUT = 20
DELL_TOKEN = "https://apigtwb2c.us.dell.com/auth/oauth/v2/token"
DELL_ENTITLEMENTS = (
    "https://apigtwb2c.us.dell.com/PROD/sbil/eapi/v5/asset-entitlements?servicetags="
)
LENOVO = (
    "https://pcsupport.lenovo.com/us/en/api/v4/upsell/redport/getIbaseInfo"
    "?serialNumber="
)


class WarrantyError(Exception):
    pass


def maker(agent) -> str:
    """Lower-case manufacturer from the hardware details, "" when unknown."""
    with suppress(Exception):
        make = agent.make_model.split()[0].lower().rstrip(",")
        if make not in ("unknown", "error"):
            return make
    return ""


def _get(method: str, url: str, **kwargs):
    host = url.split("/")[2]
    try:
        try:
            r = requests.request(method, url, timeout=TIMEOUT, **kwargs)
        except requests.RequestException as e:
            raise WarrantyError(f"connection failed ({type(e).__name__})")
        # every hop: an http one in between could redirect anywhere
        if any(not h.url.startswith("https://") for h in (*r.history, r)):
            raise WarrantyError("redirected away from https")
        if r.status_code != 200:
            raise WarrantyError(f"HTTP {r.status_code}")
        try:
            return r.json()
        except ValueError:
            raise WarrantyError("the answer is not JSON")
    except WarrantyError as e:
        DebugLog.warning(message=f"Warranty lookup at {host}: {e}")
        raise


def _date(value):
    with suppress(Exception):
        return dt.date.fromisoformat(str(value)[:10])
    return None


def dell_credentials():
    core = get_core_settings()
    try:
        return tuple(
            decrypt_secret(getattr(core, f), i) for f, i in DELL_API_INFO.items()
        )
    except InvalidToken:
        return None


def dell_token(client_id: str, client_secret: str) -> str:
    # no redirects for the requests that carry credentials
    data = _get(
        "POST",
        DELL_TOKEN,
        allow_redirects=False,
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
        },
    )
    if not isinstance(data, dict) or not data.get("access_token"):
        raise WarrantyError("Dell returned no access token")
    return data["access_token"]


def dell(serial: str, token: str) -> dict:
    data = _get(
        "GET",
        DELL_ENTITLEMENTS + quote(serial),
        allow_redirects=False,
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
    )
    asset = (
        next((a for a in data if isinstance(a, dict)), None)
        if isinstance(data, list)
        else None
    )
    if not asset or asset.get("invalid"):
        raise WarrantyError("Dell does not know this service tag")
    ents = [e for e in asset.get("entitlements") or [] if _date(e.get("endDate"))]
    if not ents:
        raise WarrantyError("Dell lists no warranty for this service tag")
    last = max(ents, key=lambda e: _date(e["endDate"]))
    starts = [d for e in ents if (d := _date(e.get("startDate")))]
    return {
        "provider": "dell",
        "product": str(asset.get("productLineDescription") or "")[:200],
        "start": str(_date(asset.get("shipDate")) or (min(starts) if starts else "")),
        "end": str(_date(last["endDate"])),
        "service_level": str(last.get("serviceLevelDescription") or "")[:200],
    }


def lenovo(serial: str) -> dict:
    data = _get("GET", LENOVO + quote(serial), headers={"Accept": "application/json"})
    info = data.get("data") if isinstance(data, dict) else None
    if not isinstance(info, dict):
        raise WarrantyError("Lenovo did not answer with warranty data")
    ents = [
        w
        for key in ("baseWarranties", "upmaWarranties")
        for w in info.get(key) or []
        if isinstance(w, dict) and _date(w.get("endDate"))
    ]
    if not ents:
        raise WarrantyError("Lenovo lists no warranty for this serial number")
    last = max(ents, key=lambda w: _date(w["endDate"]))
    starts = [d for w in ents if (d := _date(w.get("startDate")))]
    machine = info.get("machineInfo") or {}
    return {
        "provider": "lenovo",
        "product": str(machine.get("productName") or machine.get("product") or "")[
            :200
        ],
        "start": str(min(starts)) if starts else "",
        "end": str(_date(last["endDate"])),
        "service_level": str(last.get("name") or last.get("description") or "")[:200],
    }


def refresh(agent, tokens: dict) -> dict:
    """Looks up and stores one agent's warranty. tokens caches the Dell token,
    or why there is none, for a run. Returns the new warranty_status."""
    serial = (agent.serial_number or "").strip()
    make = maker(agent)
    status = {
        "provider": make,
        "product": "",
        "start": "",
        "end": "",
        "service_level": "",
        "fetched_at": djangotime.now().isoformat(),
        "error": "",
    }
    try:
        if not serial:
            raise WarrantyError("no serial number reported")
        if make == "dell":
            if "dell" not in tokens:
                try:
                    creds = dell_credentials()
                    if not creds or not all(creds):
                        raise WarrantyError(
                            "set the Dell TechDirect client id and secret in the settings"
                        )
                    tokens["dell"] = dell_token(*creds)
                except WarrantyError as e:
                    # the other Dell devices of this run get the same answer
                    tokens["dell"] = e
            if isinstance(tokens["dell"], WarrantyError):
                raise tokens["dell"]
            status |= dell(serial, tokens["dell"])
        elif make == "lenovo":
            status |= lenovo(serial)
        else:
            raise WarrantyError("no lookup for this vendor")
    except WarrantyError as e:
        status["error"] = str(e)
    except Exception as e:
        status["error"] = f"lookup failed ({type(e).__name__})"
        DebugLog.error(
            message=f"Warranty lookup for {agent.hostname}: {type(e).__name__}: {e}"[
                :1000
            ],
            agent=agent,
        )

    agent.warranty_status = status
    if not status["error"]:
        agent.warranty_end = _date(status["end"])
    # update(): looked-up data, not an edit for the audit log
    type(agent).objects.filter(pk=agent.pk).update(
        warranty_status=status, warranty_end=agent.warranty_end
    )
    return status
