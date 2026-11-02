# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""MeshCentral login cookies, signed with the server's login token key.

MeshCentral decodes them in decodeCookie(): base64 of a 12 byte nonce, the
16 byte GCM tag and the AES-256-GCM encrypted JSON (first 32 bytes of the
key), with "+" sent as "@" and "/" as "$". The JSON carries its creation time
in seconds; MeshCentral accepts the cookie for 60 minutes after that.
"""

import base64
import json
from os import urandom
from time import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _cookie(payload: dict, key: str) -> str:
    payload["time"] = int(time())
    nonce = urandom(12)
    data = json.dumps(payload, separators=(", ", ":")).encode()
    sealed = AESGCM(bytes.fromhex(key)[:32]).encrypt(nonce, data, None)
    # cryptography appends the tag, MeshCentral expects it before the data
    raw = nonce + sealed[-16:] + sealed[:-16]
    return base64.b64encode(raw).decode().replace("+", "@").replace("/", "$")


def get_auth_token(user: str, key: str) -> str:
    """?auth= cookie for control.ashx, the way meshctrl.js logs in with a key."""
    return _cookie({"userid": f"user//{user.lower()}", "domainid": ""}, key)


def get_login_token(key: str, user: str) -> str:
    """?login= cookie for the web UI; user is the full id, user//name.
    "err" when the key is unusable, the take-control URL then still opens."""
    try:
        return _cookie({"u": user.lower(), "a": 3}, key)
    except (TypeError, ValueError):
        return "err"
