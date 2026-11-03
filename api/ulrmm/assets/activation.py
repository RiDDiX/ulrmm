# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Windows and volume-licensed Office activation per device, matched to
stored license keys.

Windows names an installed key by its last five characters only, so a key
in the license store matches a device through those.
"""

import asyncio
import json
import re
from collections import defaultdict

from cryptography.fernet import InvalidToken
from django.db.models import Q

from remote.utils import decrypt_secret

from .models import HKDF_INFO, Activation

TIMEOUT = 30
CONCURRENCY = 10
MAX_PRODUCTS = 32
# SoftwareLicensingProduct.LicenseStatus
STATES = {
    0: "Unlicensed",
    1: "Licensed",
    2: "Initial grace period",
    3: "Additional grace period",
    4: "Non-genuine grace period",
    5: "Notification",
    6: "Extended grace period",
}
# no double quotes: the agent hands this to powershell as one argument
COMMAND = (
    "$p = @(Get-CimInstance SoftwareLicensingProduct "
    "-Filter 'PartialProductKey IS NOT NULL' | "
    "Select-Object Name,ProductKeyChannel,PartialProductKey,LicenseStatus); "
    "ConvertTo-Json -InputObject $p -Compress"
)
_KEY_RE = re.compile(r"\b[A-Z0-9]{5}(?:-[A-Z0-9]{5}){4}\b")
_TAIL_RE = re.compile(r"[A-Z0-9]{5}")


def payload() -> dict:
    return {
        "func": "rawcmd",
        "timeout": TIMEOUT,
        "payload": {"command": COMMAND, "shell": "powershell"},
        "run_as_user": False,
    }


def _text(value, limit: int) -> str:
    return "".join(c for c in str(value or "") if c.isprintable()).strip()[:limit]


def parse(out) -> list[dict] | None:
    """Products from the agent's reply, None when it is no usable answer."""
    if not isinstance(out, str):
        return None
    start, end = out.find("["), out.rfind("]")
    try:
        items = json.loads(out[start : end + 1]) if start != -1 else None
    except ValueError:
        return None
    if not isinstance(items, list):
        return None
    products = []
    for item in items[:MAX_PRODUCTS]:
        if not isinstance(item, dict):
            continue
        tail = str(item.get("PartialProductKey") or "").upper()
        status = item.get("LicenseStatus")
        if not _TAIL_RE.fullmatch(tail) or status not in STATES:
            continue
        products.append(
            {
                "name": _text(item.get("Name"), 200),
                "channel": _text(item.get("ProductKeyChannel"), 40),
                "partial_key": tail,
                "status": status,
            }
        )
    return products


async def collect(agents: list) -> list:
    """parse() of each agent's reply, in the order of agents."""
    data = payload()
    sem = asyncio.Semaphore(CONCURRENCY)

    async def one(agent):
        async with sem:
            try:
                out = await agent.nats_cmd(data, timeout=TIMEOUT + 10)
            except Exception:
                return None
        return parse(out)

    return await asyncio.gather(*(one(a) for a in agents))


def key_tails(lic) -> set[str]:
    """Last five characters of each product key stored in the license."""
    if not lic.key:
        return set()
    try:
        text = decrypt_secret(lic.key, HKDF_INFO).upper()
    except InvalidToken:
        return set()
    return {key[-5:] for key in _KEY_RE.findall(text)}


def matches(licenses, visible) -> dict:
    """{license pk: [device rows]} for the devices whose installed key ends
    like a key of the license; licenses without a product key are left out.
    visible as in the views: None sees all."""
    tails = {lic.pk: key_tails(lic) for lic in licenses}
    wanted = set().union(*tails.values())
    if not wanted:
        return {}
    q = Q()
    for tail in wanted:
        q |= Q(products__contains=[{"partial_key": tail}])
    found = defaultdict(list)
    rows = Activation.objects.filter(q).select_related("agent")
    for act in rows.only(
        "products",
        "collected_at",
        "agent__agent_id",
        "agent__hostname",
        "agent__display_name",
    ):
        if visible is not None and act.agent_id not in visible:
            continue
        for p in act.products:
            if p["partial_key"] in wanted:
                found[p["partial_key"]].append(
                    {
                        "agent_id": act.agent.agent_id,
                        "name": act.agent.effective_name,
                        "product": p["name"],
                        "channel": p["channel"],
                        "licensed": p["status"] == 1,
                        "status": STATES[p["status"]],
                        "collected_at": act.collected_at,
                    }
                )
    return {
        pk: [r for t in sorted(ts) for r in found[t]] for pk, ts in tails.items() if ts
    }
