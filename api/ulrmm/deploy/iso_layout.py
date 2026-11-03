# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Per-OS file layouts for the deployment ISO builder.

seed() lays out a small configuration medium that is attached next to the
unchanged installer media; full() lays out the files that go into a copy of
the installer ISO itself, with the boot menu edits that make the install
unattended. Both carry the signed deployment configuration and, when the build
is available, the pre-configured agent package. Writing the image is iso.py's
job, nothing here touches a file.
"""

import re
import shlex
import textwrap
from dataclasses import dataclass, field

from . import installers, linux, signing, windows

CONFIG_TYP = "ISOCFG"

_SEGMENT = r"[A-Za-z0-9._$@+,=~-]+"
_PATH = re.compile(rf"(/{_SEGMENT})+")


def _check(path: str) -> str:
    if not _PATH.fullmatch(path) or {".", ".."} & set(path.split("/")):
        raise ValueError(f"unsafe ISO path: {path!r}")
    try:
        from . import iso
    except Exception:
        return path
    return iso.safe_path(path)


@dataclass
class Layout:
    # seed: fixed label; full: None (the base ISO keeps its own)
    label: "str | None"
    files: list  # [(iso_path, bytes)]
    # {iso_path: fn(bytes) -> bytes} for files that exist on the base image
    edits: dict = field(default_factory=dict)
    # shown in the UI: limits, a boot argument the person has to type
    notes: list = field(default_factory=list)

    def __post_init__(self):
        for path, _ in self.files:
            _check(path)
        for path in self.edits:
            _check(path)


def config_jws(deployment) -> str:
    """The deployment's claims and enrollment token in one signed document."""
    claims = signing.claims_for(deployment)
    claims["tok"] = signing.mint_for_deployment(deployment)
    return signing.mint(claims, CONFIG_TYP)


def _config_files(deployment) -> list:
    return [
        ("/ulrmm/config.jws", config_jws(deployment).encode("ascii")),
        ("/ulrmm/config.pub", signing.public_key_pem().encode("ascii")),
    ]


# the agent package format per answer file format
_PACKAGE = {
    "autoinstall": "deb",
    "preseed": "deb",
    "kickstart": "rpm",
    "autoyast": "rpm",
    "agama": "rpm",
    "archinstall": "tgz",
}


def agent_payload(deployment, family: str, target_id: str):
    """(file name, bytes) of the pre-configured agent for the ISO, or None
    when there is no build for it. The name is short and fixed: Joliet
    allows 64 characters and the installers pick the file by its extension."""
    arch = deployment.goarch or "amd64"
    try:
        if family == "windows":
            # like the answer file: 386 deployments get the 64-bit agent
            arch = "amd64"
            chunks, _, _ = installers.setup_exe(deployment, arch)
            return f"agent-{arch}.exe", b"".join(chunks)
        tgt = linux._BY_ID.get(target_id)
        if tgt is None or arch not in installers.LINUX_ARCHES:
            return None
        if tgt["kind"] not in _PACKAGE:
            return None
        fmt = _PACKAGE[tgt["kind"]]
        build = getattr(installers, f"build_{fmt}")
        name = f"agent-{arch}.{installers.EXTENSIONS[fmt]}"
        return name, build(deployment, arch)
    except installers.Unavailable:
        return None


def _bytes(content) -> bytes:
    return content.encode("utf-8") if isinstance(content, str) else content


def _agent_notes(agent) -> list:
    if agent is None:
        return ["No agent package in the image: the agent downloads on first boot."]
    return []


# ---------------------------------------------------------------------------
# Windows

_WIN_README = """Windows unattended install
==========================

This medium holds the answer file for the install. Attach it as a second
CD/DVD drive or USB stick next to the unchanged Windows media and boot from
the Windows media. Setup finds autounattend.xml in the root of the drive and
installs Windows; after the first boot the agent downloads and enrolls.

The files hold a short-lived enrollment token and the local admin password.
Treat the medium as a secret and delete it once the device is enrolled.
"""


def _windows_files(deployment, files, agent) -> list:
    # the scripts travel inside autounattend.xml and land in a folder only
    # SYSTEM and Administrators can read; a copy in $OEM$\$$ would leave the
    # enrollment token readable in C:\Windows\Setup\Scripts
    xml = next(f for f in files if f["name"] == "autounattend.xml")
    out = [("/autounattend.xml", _bytes(xml["content"]))]
    if agent is not None:
        # Setup copies sources\$OEM$\$1 of the install media to the system
        # drive; the bootstrap looks for C:\ulrmm\*.exe before it downloads
        out.append((f"/sources/$OEM$/$1/ulrmm/{agent[0]}", agent[1]))
    return out + _config_files(deployment)


def _windows_seed(deployment, files, agent) -> Layout:
    # Setup ignores $OEM$ on a second drive, with or without
    # UseConfigurationSet, so the agent is downloaded on first boot
    out = _windows_files(deployment, files, None)
    readme = _WIN_README.replace("\n", "\r\n").encode()
    return Layout(
        "AUTOUNATTEND", out + [("/README.txt", readme)], notes=_agent_notes(None)
    )


def _windows_full(deployment, files, agent, base) -> Layout:
    notes = _agent_notes(agent)
    found = base.get("os")
    if found != "windows":
        notes.append(f"The base image does not look like Windows ({found}).")
    files = _windows_files(deployment, files, agent)
    return Layout(None, files, notes=notes)


# ---------------------------------------------------------------------------
# Linux

# kind -> volume label and the rendered files at their place on the medium
_SEEDS = {
    "kickstart": ("OEMDRV", [("ks.cfg", "/ks.cfg")]),
    "autoyast": ("OEMDRV", [("autoinst.xml", "/autoinst.xml")]),
    "agama": ("OEMDRV", [("agama-profile.json", "/agama-profile.json")]),
    "preseed": ("PRESEED", [("preseed.cfg", "/preseed.cfg")]),
    "archinstall": (
        "ARCHINSTALL",
        [
            ("user_configuration.json", "/user_configuration.json"),
            ("user_credentials.json", "/user_credentials.json"),
        ],
    ),
}

_SEED_NOTES = {
    "autoinstall": (
        "The installer still asks one confirmation unless the kernel command "
        "line carries autoinstall."
    ),
    "preseed": (
        "Debian does not auto-detect a preseed medium: boot with auto=true "
        "priority=critical preseed/file=/media/preseed.cfg, or use the full ISO."
    ),
    "agama": (
        "Agama needs inst.auto=label://OEMDRV/agama-profile.json on the "
        "kernel command line."
    ),
    "archinstall": (
        "Boot the Arch live ISO, copy the files of this drive to the live "
        "system and run sh run-archinstall.sh there."
    ),
}

# the os inspect() reports for the base images of each kind
_BASE_OS = {
    "autoinstall": ("ubuntu",),
    "preseed": ("debian",),
    "kickstart": ("rhel", "fedora"),
    "autoyast": ("suse",),
    "agama": ("suse",),
    "archinstall": ("arch",),
}


def _user_data(files) -> bytes:
    """The autoinstall file as NoCloud user-data (22.04 renders it that way
    already; newer releases render the bare autoinstall section)."""
    body = next(f["content"] for f in files if f["name"] == "autoinstall.yaml")
    if re.search(r"^autoinstall:", body, re.M):
        return body.encode()
    return ("#cloud-config\nautoinstall:\n" + textwrap.indent(body, "  ")).encode()


def _extras(target_id, files) -> dict:
    return dict(linux.bundle_extras(target_id, files))


def _linux_files(deployment, agent) -> list:
    out = _config_files(deployment)
    if agent is not None:
        out.append((f"/ulrmm/{agent[0]}", agent[1]))
    return out


def _linux_seed(target_id, kind, deployment, files, agent) -> Layout:
    rendered = {f["name"]: _bytes(f["content"]) for f in files}
    if kind == "autoinstall":
        label = "CIDATA"
        out = [
            ("/user-data", _user_data(files)),
            ("/meta-data", b"instance-id: ulrmm\n"),
        ]
    else:
        label, maps = _SEEDS[kind]
        out = [(path, rendered[name]) for name, path in maps]
    if kind == "archinstall":
        helper = _extras(target_id, files)["run-archinstall.sh"]
        out.append(("/run-archinstall.sh", helper))
    notes = [_SEED_NOTES[kind]] if kind in _SEED_NOTES else []
    return Layout(label, out + _linux_files(deployment, agent), notes=notes)


def _menu_args(argspec: str, base: dict) -> str:
    """The boot argument of an linux._ISO spec, quotes resolved."""
    arg = shlex.split(argspec.split("=", 1)[1])[0]
    if "$label" in arg:
        label = base.get("label")
        if not label:
            raise ValueError("the base image has no volume label")
        arg = arg.replace("$label", label.replace(" ", "\\x20"))
    return arg


_KERNEL = re.compile(r"^([ \t]*linux[a-z0-9]*[ \t]+\S+)", re.M)
_APPEND = re.compile(r"^([ \t]*append)(?=[^\n]*initrd=)", re.M)


def _menu_edit(path: str, arg: str):
    """linux._INJECT's sed rules for one boot menu."""

    def edit(data: bytes) -> bytes:
        text = data.decode("utf-8", "surrogateescape")
        text = _KERNEL.sub(lambda m: f"{m.group(1)} {arg}", text)
        text = _APPEND.sub(lambda m: f"{m.group(1)} {arg}", text)
        text = re.sub(r"^default harddisk$", "default linux", text, flags=re.M)
        text = re.sub(r"^timeout 0$", "timeout 50", text, flags=re.M)
        # Debian's speech menu boots on timeout without the answer file
        text = re.sub(r"^ontimeout .*\n?", "", text, flags=re.M)
        # RHEL and Fedora default to the media check, which fails on a
        # rewritten image and halts the installer
        text = re.sub(r"[ \t]+rd\.live\.check(?=[ \t]|$)", "", text, flags=re.M)
        if "grub" in path:
            text += ("" if text.endswith("\n") else "\n") + "set timeout=5\n"
        return text.encode("utf-8", "surrogateescape")

    return edit


def _linux_full(target_id, kind, deployment, files, agent, base) -> Layout:
    sources = {f["name"]: _bytes(f["content"]) for f in files}
    sources.update(_extras(target_id, files))
    if kind == "archinstall":
        # no menu to edit: the Arch live ISO is booted, then the helper run
        names = [
            ("user_configuration.json", "/user_configuration.json"),
            ("user_credentials.json", "/user_credentials.json"),
            ("run-archinstall.sh", "/run-archinstall.sh"),
        ]
        argspec = None
    else:
        names, argspec = linux._ISO.get(target_id) or linux._ISO[kind]
    out = []
    for name, path in names:
        if name in sources:
            out.append((path, sources[name]))
            continue
        # a folder of the bundle, like nocloud
        nested = [n for n in sorted(sources) if n.startswith(name + "/")]
        if not nested:
            raise ValueError(f"{name} was not rendered")
        out += [(path + n[len(name) :], sources[n]) for n in nested]
    edits = {}
    if argspec is not None:
        arg = _menu_args(argspec, base)
        edits = {m: _menu_edit(m, arg) for m in linux._ISO_MENUS.split()}
    notes = _agent_notes(agent)
    found = base.get("os")
    if found not in _BASE_OS[kind]:
        notes.append(f"The base image does not match this target ({found}).")
    if kind == "archinstall":
        notes.append(
            "Boot the Arch live ISO, copy the three files from "
            "/run/archiso/bootmnt to /root and run sh run-archinstall.sh there."
        )
    else:
        notes.append(
            "The image installs without asking and erases the target disk. "
            "Detach it after the install or boot the disk first, otherwise it "
            "installs again on the next boot."
        )
    return Layout(None, out + _linux_files(deployment, agent), edits, notes)


# ---------------------------------------------------------------------------


def _kind(target_id: str):
    """("windows", None) or ("linux", answer file kind)."""
    if windows.target(target_id) is not None:
        return "windows", None
    tgt = linux._BY_ID.get(target_id)
    if tgt is None:
        raise ValueError(f"unknown target {target_id}")
    if tgt["kind"] not in _BASE_OS:
        from . import iso

        raise iso.IsoError(f"{tgt['label']} has no installer image; use the files")
    return "linux", tgt["kind"]


def seed(target_id: str, deployment, files: list, agent) -> Layout:
    family, kind = _kind(target_id)
    if family == "windows":
        return _windows_seed(deployment, files, agent)
    return _linux_seed(target_id, kind, deployment, files, agent)


def full(target_id: str, deployment, files: list, agent, base: dict) -> Layout:
    family, kind = _kind(target_id)
    if family == "windows":
        return _windows_full(deployment, files, agent, base)
    return _linux_full(target_id, kind, deployment, files, agent, base)
