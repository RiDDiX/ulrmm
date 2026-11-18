# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import json

from ..models import SourceKind
from .base import Source, SourceError, validate

__all__ = [
    "Source",
    "SourceError",
    "for_source",
    "reach",
    "source_class",
    "validate",
]


def source_class(kind: str) -> type[Source]:
    from . import ninjaone, upstream

    classes = {
        SourceKind.UPSTREAM: upstream.Upstream,
        SourceKind.NINJAONE: ninjaone.NinjaOne,
    }
    if kind not in classes:
        raise SourceError(f"unknown source kind {kind}")
    return classes[kind]


def for_source(src) -> Source:
    try:
        secrets = json.loads(src.secret) if src.secret else {}
    except ValueError:
        secrets = {}
    return source_class(src.kind)(src.url, src.verify_tls, src.options, secrets)


def reach(src) -> tuple[tuple, bool]:
    """(platforms it can send the installer to, whether it removes its agent);
    a source read from a file has no server behind it."""
    if src.from_file:
        return (), False
    cls = source_class(src.kind)
    return cls.PUSH_PLATS, cls.REMOVES
