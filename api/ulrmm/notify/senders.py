# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""One function per channel kind. Each raises SendError with a short reason."""

import hashlib
import hmac
import json
import uuid
from email.header import Header
from urllib.parse import quote

import requests

from core.utils import _is_internal_url, get_core_settings, url_guard

TIMEOUT = 20
PRIORITY = {"info": "3", "warning": "4", "error": "5"}


class SendError(Exception):
    pass


def _send(method: str, url: str, **kwargs) -> None:
    if not url.startswith("https://"):
        raise SendError("only https:// addresses are allowed")
    if _is_internal_url(url):
        raise SendError("the address points at this server")
    try:
        # no redirects, and the socket goes to the address checked above
        with url_guard():
            r = requests.request(
                method, url, timeout=TIMEOUT, allow_redirects=False, **kwargs
            )
    except requests.RequestException as e:
        # the url can hold a token (telegram, slack, teams), keep it out
        raise SendError(f"connection failed ({type(e).__name__})")
    if not 200 <= r.status_code < 300:
        detail = " ".join(r.text[:200].split())
        raise SendError(f"HTTP {r.status_code} {detail}".strip())


def _text(n: dict) -> str:
    head = f"[{n['severity']}] {n['title']}"
    return f"{head}\n{n['body']}" if n["body"] else head


def matrix(config: dict, secret: str, n: dict) -> None:
    room = quote(config["room_id"], safe="")
    _send(
        "PUT",
        f"{config['homeserver'].rstrip('/')}/_matrix/client/v3/rooms/{room}"
        f"/send/m.room.message/{uuid.uuid4().hex}",
        headers={"Authorization": f"Bearer {secret}"},
        json={"msgtype": "m.text", "body": _text(n)},
    )


def telegram(config: dict, secret: str, n: dict) -> None:
    # no parse_mode: hostnames and messages go out as plain text
    _send(
        "POST",
        f"https://api.telegram.org/bot{secret}/sendMessage",
        json={"chat_id": config["chat_id"], "text": _text(n)},
    )


def ntfy(config: dict, secret: str, n: dict) -> None:
    title = n["title"]
    if not title.isascii():
        title = Header(title, "utf-8").encode()
    headers = {
        "Title": title,
        "Priority": PRIORITY.get(n["severity"], "5"),
        "Tags": f"{n['severity']},{n['source']}",
    }
    if secret:
        headers["Authorization"] = f"Bearer {secret}"
    server = (config.get("server") or "https://ntfy.sh").rstrip("/")
    _send(
        "POST",
        f"{server}/{config['topic']}",
        headers=headers,
        data=(n["body"] or n["title"]).encode(),
    )


def slack(config: dict, secret: str, n: dict) -> None:
    _send("POST", secret, json={"text": _text(n)})


def teams(config: dict, secret: str, n: dict) -> None:
    # an adaptive card: Workflows webhooks need one, the old connectors take it too
    card = {
        "type": "AdaptiveCard",
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "version": "1.4",
        "body": [{"type": "TextBlock", "text": _text(n), "wrap": True}],
    }
    _send(
        "POST",
        secret,
        json={
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": card,
                }
            ],
        },
    )


def webhook(config: dict, secret: str, n: dict) -> None:
    body = json.dumps(
        {k: n.get(k) for k in ("source", "severity", "title", "body", "agent_id")}
        | {"alert_id": n.get("alert"), "escalation_level": n["escalation_level"]},
        separators=(",", ":"),
    ).encode()
    headers = {"Content-Type": "application/json"}
    if secret:
        digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        headers["X-Signature"] = f"sha256={digest}"
    _send("POST", config["url"], headers=headers, data=body)


def email(config: dict, secret: str, n: dict) -> None:
    # test=True returns the smtp error instead of only logging it
    msg, ok = get_core_settings().send_mail(
        n["title"],
        _text(n),
        override_recipients=config.get("recipients") or [],
        test=True,
    )
    if not ok:
        raise SendError(msg[:200])
