# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Expected SHA-256 of a mirror download, read from the mirror's sums file."""

import os
import re
from urllib.parse import unquote, urlparse

import requests

from . import tasks

MAX_BYTES = 1024 * 1024
_GNU = re.compile(r"^([0-9a-fA-F]{64})\s+\*?(.+)$")
_BSD = re.compile(r"^SHA256 \((.+)\) = ([0-9a-fA-F]{64})$")


def _name(path: str) -> str:
    return os.path.basename(unquote(path).replace("\\", "/"))


def expected_sha256(url: str, sha256_url: str) -> str:
    if urlparse(sha256_url).scheme != "https" or urlparse(url).scheme != "https":
        raise ValueError("Only https URLs can be used for checksums")
    want = _name(urlparse(url).path)
    buf = b""
    try:
        with tasks._open(sha256_url, 0) as r:
            r.raise_for_status()
            for chunk in r.iter_content(65536):
                buf += chunk
                if len(buf) > MAX_BYTES:
                    break
    except requests.RequestException as e:
        raise ValueError(f"The sums file could not be fetched: {e}") from e
    for line in buf[:MAX_BYTES].decode("utf-8", "replace").splitlines():
        if m := _GNU.match(line.strip()):
            digest, name = m.groups()
        elif m := _BSD.match(line.strip()):
            name, digest = m.groups()
        else:
            continue
        if _name(name) == want:
            return digest.lower()
    raise ValueError(f"no checksum for {want} in the sums file")
