# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Small YAML emitter for the Ubuntu autoinstall answer file.

Block style only, enough for the subset of YAML autoinstall needs: mappings,
sequences, strings, ints, bools and null. No external dependency.
"""

_PLAIN_OK = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" "_-./@"
)
# strings that would be read as something other than a string if left plain
_RESERVED = {
    "true",
    "false",
    "yes",
    "no",
    "on",
    "off",
    "null",
    "none",
    "~",
    "",
}


def _needs_quote(s: str) -> bool:
    if s.lower() in _RESERVED or s.strip() != s:
        return True
    if s[0] in "0123456789-":
        # looks like a number or starts with a dash
        return True
    return any(c not in _PLAIN_OK for c in s)


def _scalar(value) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    text = str(value)
    if _needs_quote(text):
        return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return text


def _emit(value, indent: int, out: list) -> None:
    pad = "  " * indent
    if isinstance(value, dict):
        if not value:
            out[-1] += " {}"
            return
        for key, val in value.items():
            if isinstance(val, dict) and val:
                out.append(f"{pad}{key}:")
                _emit(val, indent + 1, out)
            elif isinstance(val, list) and val:
                out.append(f"{pad}{key}:")
                _emit(val, indent, out)
            else:
                out.append(f"{pad}{key}:")
                out[-1] += f" {_inline(val)}"
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, (dict, list)) and item:
                out.append(f"{pad}-")
                _emit(item, indent + 1, out)
            else:
                out.append(f"{pad}- {_inline(item)}")
    else:
        out.append(f"{pad}{_scalar(value)}")


def _inline(value) -> str:
    if isinstance(value, dict):
        return "{}"
    if isinstance(value, list):
        return "[]"
    return _scalar(value)


def dump(data: dict) -> str:
    """A mapping or sequence as block-style YAML text (trailing newline)."""
    out: list = []
    _emit(data, 0, out)
    return "\n".join(out) + "\n"


def _demo() -> None:
    import yaml

    sample = {
        "version": 1,
        "identity": {"username": "admin", "password": "$6$abc$def", "hostname": "h"},
        "ssh": {"install-server": True, "authorized-keys": ["ssh-ed25519 AAAA x@y"]},
        "late-commands": ["sh -c 'echo hi'", "systemctl enable foo.service"],
        "packages": ["curl"],
        "proxy": None,
        "keyboard": {"layout": "us"},
        "empty": {},
    }
    text = dump(sample)
    assert yaml.safe_load(text) == sample, text
    # a value that must be quoted to stay a string
    assert yaml.safe_load(dump({"a": "yes"}))["a"] == "yes"
    assert yaml.safe_load(dump({"a": "12:30"}))["a"] == "12:30"
    print("yamlish ok")


if __name__ == "__main__":
    _demo()
