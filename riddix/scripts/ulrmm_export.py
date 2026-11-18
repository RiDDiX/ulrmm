#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Export a compatible RMM server into one encrypted file for the ulrmm
import (Global Settings -> Import), for when the old server is gone before
ulrmm runs.

    python3 ulrmm_export.py https://api.old.example [-o FILE] [--no-verify-tls]

The API key of a superuser comes from ULRMM_EXPORT_API_KEY or a prompt. The
file holds the server's raw API answers, encrypted with a key that is shown
once; ulrmm reads them the way it reads a live server. Needs Python 3.9+ and
the cryptography package; the old server's own Python environment has it.
"""

import argparse
import base64
import datetime as dt
import getpass
import gzip
import http.client
import json
import os
import re
import secrets
import ssl
import sys
import urllib.error
import urllib.request
from urllib.parse import urlencode, urlsplit

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
except ImportError:
    AESGCM = None

FORMAT = 1
MAGIC = b"ULRMMEXP"
INFO = b"ulrmm export file"
TIMEOUT = 30
# mirror MAX_FILE and MAX_PLAIN of api/ulrmm/importers/sources/file.py
MAX_FILE = 64 * 1024 * 1024
MAX_PLAIN = 256 * 1024 * 1024
# a device's detail holds its inventory; ulrmm reads only the small keys
MAX_VALUE = 4096
AGENT_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,255}")
# the import's rule for a source address (importers URL_RE)
URL_RE = re.compile(r"^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$")
REPORTING = (
    "/reporting/htmltemplates/",
    "/reporting/templates/",
    "/reporting/dataqueries/",
)
LISTS = (
    "/checks/",
    "/tasks/",
    "/core/urlaction/",
    "/alerts/templates/",
    "/automation/policies/",
    "/accounts/roles/",
    "/accounts/users/",
    "/scripts/snippets/",
    "/core/keystore/",
)


class NotFound(Exception):
    pass


class ExportError(Exception):
    pass


def answer_key(path: str, params=None) -> str:
    return f"{path}?{urlencode(params)}" if params else path


def _rows(data) -> list:
    return [d for d in data if isinstance(d, dict)] if isinstance(data, list) else []


def trim(detail):
    if not isinstance(detail, dict):
        return detail
    return {k: v for k, v in detail.items() if len(json.dumps(v).encode()) <= MAX_VALUE}


def collect(get, say=lambda msg: None) -> dict:
    """The answers the import's fetch asks for, keyed like its requests.
    get(path, params) returns the parsed JSON or raises NotFound."""
    answers = {}

    def read(path, params=None, kind=list):
        answers[answer_key(path, params)] = data = get(path, params)
        # what the import refuses is refused here, while the server still runs
        if kind is list and not isinstance(data, list):
            raise ExportError(f"{path} gave an unexpected answer")
        return data

    read("/core/customfields/")
    clients = _rows(read("/clients/"))
    read("/agents/notes/")
    sites = [
        str(s.get("id"))
        for c in clients
        for s in c.get("sites") or []
        if isinstance(s, dict)
    ]
    say(f"{len(clients)} clients, {len(sites)} sites")
    devices = []
    for site in sites:
        devices += _rows(read("/agents/", {"site": site}))
    say(f"{len(devices)} devices")

    scripts = 0
    for s in _rows(read("/scripts/", {"showCommunityScripts": "false"})):
        if s.get("script_type") == "userdefined":
            # a detail that is no dict is skipped by the import as well
            read(f"/scripts/{int(s['id'])}/", kind=dict)
            scripts += 1
    say(f"{scripts} scripts")
    read("/agents/", {"detail": "false"})
    for path in LISTS:
        read(path)
    for path in REPORTING:
        try:
            read(path)
        except NotFound:
            # servers without the reporting module
            pass

    details = 0
    for d in devices:
        ref = d.get("agent_id")
        if not isinstance(ref, str) or not AGENT_ID_RE.fullmatch(ref):
            continue
        path = f"/agents/{ref}/"
        try:
            detail = get(path, None)
        except NotFound:
            continue
        if not isinstance(detail, dict):
            continue
        answers[path] = trim(detail)
        details += 1
        if details % 50 == 0:
            say(f"{details} of {len(devices)} device details")
    say(f"{details} device details")
    return answers


def origin(url: str) -> str:
    """The address as the import stores it; ValueError when it does not fit."""
    if not URL_RE.fullmatch(url):
        raise ValueError(url)
    parts = urlsplit(url)
    # one server, one spelling: the import compares origins as text
    port = f":{parts.port}" if parts.port not in (None, 443) else ""
    host = parts.hostname.rstrip(".")
    ret = f"https://{host}{port}{parts.path.rstrip('/')}"
    if not host or not URL_RE.fullmatch(ret):
        raise ValueError(url)
    return ret


def _aes_key(secret: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=INFO).derive(
        secret
    )


def seal(answers: dict, origin: str, kind: str = "upstream") -> tuple:
    """(file bytes, file key); origin binds the file to its server."""
    made = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    raw = json.dumps(
        {"kind": kind, "made": made, "origin": origin, "answers": answers}
    ).encode()
    if len(raw) > MAX_PLAIN:
        raise ExportError(
            f"the export holds {len(raw) // 2**20} MB of data, "
            f"the import takes at most {MAX_PLAIN // 2**20} MB"
        )
    plain = gzip.compress(raw)
    secret = secrets.token_bytes(20)
    header = MAGIC + bytes([FORMAT])
    nonce = secrets.token_bytes(12)
    body = AESGCM(_aes_key(secret)).encrypt(nonce, plain, header)
    if len(header + nonce + body) > MAX_FILE:
        raise ExportError(
            f"the file would be {len(header + nonce + body) // 2**20} MB, "
            f"the import takes at most {MAX_FILE // 2**20} MB"
        )
    words = base64.b32encode(secret).decode()
    key = "-".join(re.findall("....", words))
    return header + nonce + body, key


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # a key never goes to another host
        return None


def http_get(base: str, api_key: str, verify_tls: bool = True):
    ctx = ssl.create_default_context()
    if not verify_tls:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(
        _NoRedirect(), urllib.request.HTTPSHandler(context=ctx)
    )
    base = base.rstrip("/")

    def get(path, params=None):
        req = urllib.request.Request(
            base + answer_key(path, params),
            headers={"X-API-KEY": api_key, "Accept": "application/json"},
        )
        try:
            with opener.open(req, timeout=TIMEOUT) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                raise NotFound(path)
            if 300 <= e.code < 400:
                raise ExportError(f"{path} answered with a redirect, refused")
            if e.code in (401, 403):
                raise ExportError(f"the API key was refused ({e.code})")
            raise ExportError(f"{path} answered {e.code}")
        except urllib.error.URLError as e:
            raise ExportError(f"{path}: {e.reason}")
        except (OSError, ValueError, http.client.HTTPException) as e:
            raise ExportError(f"{path}: {type(e).__name__}")

    return get


def write_new(path: str, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
    except BaseException:
        # only the file opened here, never one that was there before
        os.unlink(path)
        raise


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("url", help="address of the old server's API, https://...")
    p.add_argument("-o", "--output", help="file to write (never overwritten)")
    p.add_argument("--no-verify-tls", action="store_true")
    args = p.parse_args(argv)

    if AESGCM is None:
        print(
            "The cryptography package is missing: pip install cryptography\n"
            "The old server's own Python environment already has it.",
            file=sys.stderr,
        )
        return 1
    try:
        base = origin(args.url)
    except ValueError:
        print(
            "The address must look like https://host[:port][/path] "
            "(letters, digits, dots, dashes; no user, query or fragment).",
            file=sys.stderr,
        )
        return 1
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    out = args.output or f"ulrmm-export-{stamp}.bin"
    if os.path.lexists(out):
        print(f"{out} exists already, choose another name.", file=sys.stderr)
        return 1
    folder = os.path.dirname(os.path.abspath(out))
    if not os.path.isdir(folder) or not os.access(folder, os.W_OK | os.X_OK):
        print(f"{folder} is no directory this user can write to.", file=sys.stderr)
        return 1
    api_key = os.environ.get("ULRMM_EXPORT_API_KEY") or getpass.getpass(
        "API key of a superuser: "
    )
    if not api_key:
        print("No API key given.", file=sys.stderr)
        return 1

    try:
        answers = collect(http_get(base, api_key, not args.no_verify_tls), say=print)
    except NotFound as e:
        print(f"{e} answered 404, nothing was written.", file=sys.stderr)
        return 1
    except ExportError as e:
        print(f"{e}; nothing was written.", file=sys.stderr)
        return 1
    try:
        data, key = seal(answers, base)
    except ExportError as e:
        print(f"{e}; nothing was written.", file=sys.stderr)
        return 1
    try:
        write_new(out, data)
    except OSError as e:
        print(f"{out}: {e.strerror}; nothing was written.", file=sys.stderr)
        return 1
    print(
        f"\nWritten: {os.path.abspath(out)}\n"
        f"File key: {key}\n\n"
        "The key is shown only this once and stored nowhere. The file holds the\n"
        "old server's secrets (key store values, script bodies, web hook\n"
        "headers, user e-mail addresses), encrypted with that key. Keep file\n"
        "and key apart. Keep the file until every part you want is imported,\n"
        "then delete it.\n"
        "In ulrmm: Global Settings -> Import, upload the file and enter the key."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
