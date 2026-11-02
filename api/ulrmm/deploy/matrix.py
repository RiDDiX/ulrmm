# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""The deployment target matrix: Windows targets from windows.py merged with
the Linux targets from linux.py (lane S-LNX), plus the installer catalogue the
public link serves. The builder views read build_matrix() and dispatch render
and bundling by family through module_for().
"""

from django.conf import settings

from . import signing, windows

# the agent installers the public /clients/<uid>/deploy/ link hands out
INSTALLERS = [
    {
        "fmt": "exe",
        "plat": "windows",
        "arches": ["amd64", "386"],
        "label": "Windows setup (.exe)",
    },
    {
        "fmt": "ps1",
        "plat": "windows",
        "arches": ["amd64", "386"],
        "label": "Windows bootstrap (PowerShell)",
    },
    {
        "fmt": "deb",
        "plat": "linux",
        "arches": ["amd64", "386", "arm64", "arm"],
        "label": "Debian/Ubuntu package (.deb)",
    },
    {
        "fmt": "rpm",
        "plat": "linux",
        "arches": ["amd64", "386", "arm64", "arm"],
        "label": "RHEL/SUSE package (.rpm)",
    },
    {
        "fmt": "tgz",
        "plat": "linux",
        "arches": ["amd64", "386", "arm64", "arm"],
        "label": "Portable archive (.tar.gz)",
    },
    {
        "fmt": "sh",
        "plat": "linux",
        "arches": [],
        "label": "Shell bootstrap (auto-detect arch)",
    },
]


def _linux():
    """The S-LNX module, or None until that lane lands. Patched in tests."""
    try:
        from . import linux
    except ImportError:
        return None
    return linux


def all_targets():
    targets = list(windows.TARGETS)
    linux = _linux()
    if linux is not None:
        targets += list(getattr(linux, "TARGETS", []))
    return targets


def module_for(target_id: str):
    """The module that validates and renders a target, by family."""
    if windows.target(target_id) is not None:
        return windows
    linux = _linux()
    if linux is not None and target_id in {t["id"] for t in linux.TARGETS}:
        return linux
    return None


def _win_signed() -> bool:
    # Authenticode signing is configured for the server process
    return bool(getattr(settings, "ULRMM_SIGN_WIN_PFX", ""))


# the target keys the API shows; the rest is builder-internal
_PUBLIC_KEYS = ("id", "family", "group", "label", "formats", "capabilities", "notes")


# optional per-target keys, sent only when the target carries them
_OPTIONAL_KEYS = ("release", "downloads", "presets")


def _public(target: dict) -> dict:
    out = {key: target[key] for key in _PUBLIC_KEYS}
    out.update({key: target[key] for key in _OPTIONAL_KEYS if key in target})
    module = module_for(target["id"])
    out["defaults"] = module.profile_defaults(target["id"])
    # labels, help and choices (or a choices_ref into choice_sets) per
    # profile path; the form infers the rest
    fields = getattr(module, "profile_fields", None)
    out["fields"] = fields(target["id"]) if fields else {}
    return out


def choice_sets() -> dict:
    """The long choice lists, sent once; a field names one in "choices_ref"
    instead of an inline "choices" list (inline stays allowed)."""
    sets = {}
    for module in (windows, _linux()):
        # a module without choice_sets() keeps its choices inline
        sets.update(getattr(module, "choice_sets", dict)())
    return sets


def build_matrix() -> dict:
    return {
        "targets": [_public(t) for t in all_targets()],
        "choice_sets": choice_sets(),
        "installers": INSTALLERS,
        "pubkey_b64": signing.public_key_b64(),
        "pubkey_pem": signing.public_key_pem(),
        "kid": signing.key_id(),
        "dist_ok": signing.dist_pubkey_ok(),
        "agent_version": settings.LATEST_AGENT_VER,
        "win_signed": _win_signed(),
    }
