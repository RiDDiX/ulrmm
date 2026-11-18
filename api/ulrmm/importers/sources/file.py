# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""A source read from a file made by riddix/scripts/ulrmm_export.py.

The file holds the other server's raw API answers, not a snapshot: they are
replayed through the source's own fetch() and validate(), so a file made
today still reads after the mapping or SNAPSHOT_VERSION changed.

    b"ULRMMEXP" + format byte, 12-byte nonce, AES-256-GCM(gzip(JSON)) with the
    9-byte header as associated data; JSON {kind, made, answers}

The AES key is HKDF-SHA256 of the 20-byte file key the exporter showed in
base32."""

import base64
import binascii
import json
import re
import zlib
from urllib.parse import urlencode

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..models import SourceKind
from . import source_class
from .base import URL_RE, NotFound, SourceError, validate

FORMAT = 1
MAGIC = b"ULRMMEXP"
INFO = b"ulrmm export file"
MAX_FILE = 64 * 1024 * 1024
MAX_PLAIN = 256 * 1024 * 1024
HEADER = len(MAGIC) + 1
NOT_OURS = "This is not a ulrmm export file."
BAD_KEY = "The file key does not fit, or the file is damaged."


def _aes_key(key: str) -> bytes:
    raw = "".join(key.split()).replace("-", "").upper()
    try:
        secret = base64.b32decode(raw)
    except (binascii.Error, ValueError):
        raise SourceError(BAD_KEY)
    if len(secret) != 20:
        raise SourceError(BAD_KEY)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=INFO).derive(
        secret
    )


def _plain(data: bytes, key: str) -> bytes:
    if len(data) > MAX_FILE:
        raise SourceError(f"The file is larger than {MAX_FILE // 2**20} MB.")
    if len(data) < HEADER or data[: len(MAGIC)] != MAGIC:
        raise SourceError(NOT_OURS)
    if data[len(MAGIC)] < FORMAT:
        raise SourceError(
            "This file was made by an older exporter. "
            "Make it again with the current one."
        )
    if data[len(MAGIC)] > FORMAT:
        raise SourceError(
            "This file was made by a newer exporter. Update this installation first."
        )
    aes = _aes_key(key)
    nonce, body = data[HEADER : HEADER + 12], data[HEADER + 12 :]
    if len(nonce) != 12:
        raise SourceError(BAD_KEY)
    try:
        packed = AESGCM(aes).decrypt(nonce, body, data[:HEADER])
    except InvalidTag:
        raise SourceError(BAD_KEY)
    unzip = zlib.decompressobj(wbits=31)
    try:
        plain = unzip.decompress(packed, MAX_PLAIN)
    except zlib.error:
        raise SourceError(NOT_OURS)
    if unzip.unconsumed_tail:
        raise SourceError(f"The file unpacks to more than {MAX_PLAIN // 2**20} MB.")
    if not unzip.eof:
        raise SourceError(NOT_OURS)
    return plain


def _replay(cls, answers: dict) -> dict:
    # placeholders: fetch() checks that its secrets are set, nothing is sent
    client = cls(
        "https://export.file.invalid", True, {}, dict.fromkeys(cls.SECRETS, "-")
    )
    client.session = None

    def call(method, path, timeout=None, **kwargs):
        params = kwargs.get("params")
        key = f"{path}?{urlencode(params)}" if params else path
        if method != "GET" or key not in answers:
            raise NotFound(f"{path} answered 404")
        # once each: a repeated id in the file must not multiply the work
        return answers.pop(key)

    client.call = call
    try:
        return validate(client.fetch())
    except SourceError as e:
        raise SourceError(f"The file cannot be used: {e}")


def read(data: bytes, key: str, kind: str) -> tuple[dict, str]:
    """(validated snapshot, address of the server it was read from), or
    SourceError."""
    try:
        made = json.loads(_plain(data, key))
    except ValueError:
        raise SourceError(NOT_OURS)
    if (
        not isinstance(made, dict)
        or not isinstance(made.get("kind"), str)
        or not isinstance(made.get("answers"), dict)
        or not isinstance(made.get("origin"), str)
        or len(made["origin"]) > 255
        or not re.fullmatch(URL_RE, made["origin"])
    ):
        raise SourceError(NOT_OURS)
    if made["kind"] not in SourceKind.values:
        raise SourceError(NOT_OURS)
    if made["kind"] != kind:
        raise SourceError(
            f"This file holds an export of a {SourceKind(made['kind']).label}, "
            f"the source is a {SourceKind(kind).label}."
        )
    cls = source_class(kind)
    if not cls.FILE:
        raise SourceError(f"{SourceKind(kind).label} cannot be imported from a file.")
    return _replay(cls, made["answers"]), made["origin"]
