# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Installers behind a deployment's public link: the setup exe with an
appended enrollment block, .deb, .rpm and .tar.gz packages and the bootstrap
scripts. Everything is built per request in memory; only a setup exe the
server signs again goes through a private tmpfs directory.
"""

import asyncio
import base64
import gzip
import hashlib
import io
import logging
import os
import re
import shutil
import struct
import subprocess
import tarfile
import tempfile
import unicodedata

from django.conf import settings
from django.core.cache import cache

from agents.utils import (
    _MESH_LINUX_IDENT,
    _dist_dir,
    get_install_agent_url,
    install_artifact_sha256,
    render_linux_install,
)
from core.utils import (
    get_branding,
    get_core_settings,
    get_mesh_device_id,
    get_mesh_ws_url,
    mesh_installer_sha256,
)
from ulrmm.agent_ident import (
    agent_artifact,
    agent_ident,
    brand_agent_name,
    render_agent_script,
)
from ulrmm.constants import AgentPlat

from . import signing

logger = logging.getLogger("ulrmm")

WIN_ARCHES = ("amd64", "386")
LINUX_ARCHES = ("amd64", "386", "arm64", "arm")
ARCHES = {
    "exe": WIN_ARCHES,
    "ps1": WIN_ARCHES,
    "deb": LINUX_ARCHES,
    "rpm": LINUX_ARCHES,
    "tgz": LINUX_ARCHES,
    "sh": LINUX_ARCHES,
    "sig": LINUX_ARCHES,
}
EXTENSIONS = {
    "exe": "exe",
    "ps1": "ps1",
    "deb": "deb",
    "rpm": "rpm",
    "tgz": "tar.gz",
    "sh": "sh",
    "sig": "sh.sig",
}
CONTENT_TYPES = {
    "exe": "application/octet-stream",
    "ps1": "text/plain; charset=utf-8",
    "deb": "application/vnd.debian.binary-package",
    "rpm": "application/x-rpm",
    "tgz": "application/gzip",
    "sh": "text/x-shellscript; charset=utf-8",
    "sig": "text/plain; charset=utf-8",
}
DEB_ARCH = {"amd64": "amd64", "386": "i386", "arm64": "arm64", "arm": "armhf"}
# rpm arch and the lead's archnum (rpmrc)
RPM_ARCH = {
    "amd64": ("x86_64", 1),
    "386": ("i686", 1),
    "arm64": ("aarch64", 19),
    "arm": ("armv7hl", 12),
}
LICENSE = "FSL-1.1-ALv2"
FOOTER_MAGIC = b"ULRMMENR"
HEAD_BYTES = 4096
CHUNK = 1024 * 1024
SIGN_TIMEOUT = 120
MESH_ID_TTL = 300
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


Unavailable = signing.Unavailable


def _text(value) -> str:
    return " ".join(_CTRL.sub(" ", str(value or "")).split())


def download_name(deployment, fmt: str, arch=None) -> str:
    site = deployment.site
    parts = [get_branding().product_name or "agent", site.client.name, site.name]
    if arch:
        parts.append(arch)
    clean = []
    for part in parts:
        ascii_part = unicodedata.normalize("NFKD", str(part)).encode("ascii", "ignore")
        part = re.sub(r"[^A-Za-z0-9]+", "-", ascii_part.decode())[:40].strip("-")
        if part:
            clean.append(part)
    return "-".join(clean or ["agent"]) + "." + EXTENSIONS[fmt]


def dist_file(plat: str, arch: str):
    path = _dist_dir() / agent_artifact(settings.LATEST_AGENT_VER, plat, arch)
    if not path.is_file():
        raise Unavailable(f"agent build needed: run update.sh (no {plat} {arch} build)")
    return path


def _mesh_builds(arches) -> dict:
    """{arch: (mesh agent url, its sha256 or "")} of the Linux arches."""
    core = get_core_settings()
    group = core.mesh_device_group
    key = "deploy_mesh_id:" + hashlib.sha256(str(group).encode()).hexdigest()[:16]
    mesh_id = cache.get(key)
    if not mesh_id:
        try:
            mesh_id = asyncio.run(get_mesh_device_id(get_mesh_ws_url(), group))
        except Exception as e:
            raise Unavailable(f"MeshCentral: {e}") from e
        # the link is public, so not every download opens a MeshCentral session
        cache.set(key, mesh_id, MESH_ID_TTL)
    return {
        a: (
            f"{core.mesh_site}/meshagents?id={mesh_id}&installflags=2"
            f"&meshinstall={_MESH_LINUX_IDENT[a]}",
            mesh_installer_sha256(
                ident=_MESH_LINUX_IDENT[a],
                plat=AgentPlat.LINUX,
                mesh_device_id=mesh_id,
                mesh_site=core.mesh_site,
            ),
        )
        for a in arches
    }


# scripts


def _render_sh(deployment, builds, *, arch, local_binary) -> str:
    _, url, sha, mesh, mesh_sha = builds[0] if arch else ("",) * 5
    return render_linux_install(
        download_url="" if local_binary else url,
        sha256=sha,
        mesh_url=mesh,
        mesh_sha256=mesh_sha,
        client=str(deployment.site.client_id),
        site=str(deployment.site_id),
        agent_type=deployment.mon_type,
        token="",
        api=signing.api_url(),
        enroll="" if local_binary else signing.mint_for_deployment(deployment),
        builds="" if arch else "\n".join(" ".join(b).rstrip() for b in builds),
        local_binary=local_binary,
    )


def bootstrap_sh(deployment, *, arch=None, local_binary=False) -> str:
    """The deployment's Linux install script. Without arch it carries every
    local build and picks one by uname -m. local_binary expects the agent
    binary and enroll.jws next to the script, as the packages ship them."""
    if arch is None and local_binary:
        raise ValueError("local_binary needs an arch")
    if arch is not None and arch not in LINUX_ARCHES:
        raise ValueError(f"there is no Linux build for {arch}")
    wanted = [arch] if arch else LINUX_ARCHES
    shas = {a: install_artifact_sha256(AgentPlat.LINUX, a) for a in wanted}
    arches = [a for a, sha in shas.items() if sha]
    if not arches:
        raise Unavailable("agent build needed: run update.sh (no Linux build)")
    meshes = _mesh_builds(arches)
    builds = [
        (a, get_install_agent_url(goarch=a, plat=AgentPlat.LINUX), shas[a], *meshes[a])
        for a in arches
    ]
    return _render_sh(deployment, builds, arch=arch, local_binary=local_binary)


def sh_signature(deployment, arch=None) -> bytes:
    """base64 Ed25519 signature of the exact fmt=sh body for the same arch."""
    body = bootstrap_sh(deployment, arch=arch).encode()
    return base64.b64encode(signing.signing_key().sign(body))


def bootstrap_ps1(deployment, *, arch="amd64") -> str:
    """The deployment's Windows bootstrap script: generic setup exe from
    agentdist, sha256 check, silent setup, then -m install -enroll."""
    if arch not in WIN_ARCHES:
        raise ValueError(f"there is no Windows build for {arch}")
    sha = install_artifact_sha256(AgentPlat.WINDOWS, arch)
    if not sha:
        raise Unavailable("agent build needed: run update.sh (no Windows build)")
    flags = deployment.install_flags or {}
    values = {
        "innosetupchange": agent_artifact(
            settings.LATEST_AGENT_VER, AgentPlat.WINDOWS, arch
        ),
        "clientchange": str(deployment.site.client_id),
        "sitechange": str(deployment.site_id),
        "apichange": signing.api_url(),
        "atypechange": deployment.mon_type,
        "powerchange": str(int(bool(flags.get("power")))),
        "rdpchange": str(int(bool(flags.get("rdp")))),
        "pingchange": str(int(bool(flags.get("ping")))),
        "downloadchange": get_install_agent_url(goarch=arch, plat=AgentPlat.WINDOWS),
        "tokenchange": "",
        "sha256change": sha,
        "enrollchange": signing.mint_for_deployment(deployment),
    }
    template = render_agent_script(
        settings.BASE_DIR / "core" / "installer.ps1", agent_ident()
    )
    # one pass; the values sit between single quotes
    pattern = re.compile("|".join(re.escape(k) for k in values))
    return pattern.sub(lambda m: values[m.group(0)].replace("'", "''"), template)


# setup exe


def footer(jws: str, offset: int) -> bytes:
    """The enrollment block for a file of offset bytes; it ends on an 8-byte
    boundary, where a signature's certificate table may follow."""
    raw = jws.encode("ascii")
    pad = -(offset + len(raw)) % 8
    return bytes(pad) + raw + struct.pack("<Q", len(raw)) + FOOTER_MAGIC


def pe_cert_entry(head: bytes):
    """(file offset of the security directory entry, certificate table offset,
    table size) of a PE file, None for anything else."""
    try:
        if head[:2] != b"MZ":
            return None
        pe = struct.unpack_from("<I", head, 0x3C)[0]
        if head[pe : pe + 4] != b"PE\0\0":
            return None
        opt_size = struct.unpack_from("<H", head, pe + 20)[0]
        opt = pe + 24
        dirs = {0x10B: 96, 0x20B: 112}.get(struct.unpack_from("<H", head, opt)[0])
        # NumberOfRvaAndSizes sits right before the data directories
        if dirs is None or struct.unpack_from("<I", head, opt + dirs - 4)[0] < 5:
            return None
        entry = opt + dirs + 4 * 8
        if entry + 8 > opt + opt_size:
            return None
        return (entry, *struct.unpack_from("<II", head, entry))
    except struct.error:
        return None


def win_signer():
    """osslsigncode settings from the keys riddix/agents/sign.sh reads
    (environment first, then local_settings.py), None when signing is off."""

    def value(name):
        return os.environ.get(name) or str(getattr(settings, name, "") or "")

    pfx, pass_file = value("ULRMM_SIGN_WIN_PFX"), value("ULRMM_SIGN_WIN_PASS_FILE")
    tool = shutil.which("osslsigncode")
    if not (pfx and pass_file and tool):
        return None
    if not (os.access(pfx, os.R_OK) and os.access(pass_file, os.R_OK)):
        return None
    return {
        "tool": tool,
        "pfx": pfx,
        "pass_file": pass_file,
        "ts": value("ULRMM_SIGN_TIMESTAMP_URL"),
    }


def _exe_chunks(fh, head: bytes, end: int, block: bytes):
    try:
        yield head
        fh.seek(len(head))
        left = end - len(head)
        while left > 0:
            chunk = fh.read(min(CHUNK, left))
            if not chunk:
                raise OSError("the setup exe changed while it was read")
            left -= len(chunk)
            yield chunk
        yield block
    finally:
        fh.close()


def _sign(signer, chunks) -> bytes:
    shm = "/dev/shm" if os.path.isdir("/dev/shm") else None
    with tempfile.TemporaryDirectory(prefix="ulrmm-sign-", dir=shm) as tmp:
        src, out = os.path.join(tmp, "in.exe"), os.path.join(tmp, "out.exe")
        with open(src, "wb") as fh:
            for chunk in chunks:
                fh.write(chunk)
        cmd = [signer["tool"], "sign", "-pkcs12", signer["pfx"]]
        cmd += ["-readpass", signer["pass_file"], "-h", "sha256"]
        if signer["ts"]:
            cmd += ["-ts", signer["ts"]]
        try:
            subprocess.run(
                cmd + ["-in", src, "-out", out],
                check=True,
                capture_output=True,
                timeout=SIGN_TIMEOUT,
            )
            with open(out, "rb") as fh:
                return fh.read()
        except (OSError, subprocess.SubprocessError) as e:
            logger.warning(f"deploy: Authenticode signing failed: {e}")
            raise Unavailable("signing the setup exe failed") from e


def setup_exe(deployment, arch: str):
    """(chunks, size, signed): the generic setup exe with the deployment's
    enrollment block. A signature is stripped first; the block then ends where
    a new signature starts."""
    jws = signing.mint_for_deployment(deployment)
    fh = open(dist_file(AgentPlat.WINDOWS, arch), "rb")
    try:
        size = os.fstat(fh.fileno()).st_size
        head = bytearray(fh.read(HEAD_BYTES))
        end = size
        cert = pe_cert_entry(head)
        if cert and cert[2]:
            entry, end, _ = cert
            if not 0 < end <= size:
                raise Unavailable("the setup exe has a broken certificate table")
            head[entry : entry + 8] = bytes(8)
        head = bytes(head[:end])
        block = footer(jws, end)
        signer = win_signer()
        if signer is None:
            return _exe_chunks(fh, head, end, block), end + len(block), False
        body = _sign(signer, _exe_chunks(fh, head, end, block))
        return [body], len(body), True
    except BaseException:
        fh.close()
        raise


# packages


def _package_name() -> str:
    bin_name = agent_ident()["identNixBin"]
    return re.sub(r"[^a-z0-9+.-]+", "-", bin_name.lower()).strip("-+.") or "agent"


def _payload(deployment, arch: str):
    """(binary name, payload dir, [(name, mode, data)]) of a Linux package."""
    bin_name = agent_ident()["identNixBin"]
    binary = dist_file(AgentPlat.LINUX, arch).read_bytes()
    sha = hashlib.sha256(binary).hexdigest()
    builds = [(arch, "", sha, *_mesh_builds([arch])[arch])]
    script = _render_sh(deployment, builds, arch=arch, local_binary=True)
    jws = signing.mint_for_deployment(deployment) + "\n"
    files = [
        ("enroll.jws", 0o600, jws.encode("ascii")),
        ("install.sh", 0o755, script.encode()),
        (bin_name, 0o755, binary),
    ]
    return bin_name, f"/usr/lib/{bin_name}-installer", sorted(files)


def _maint_scripts(bin_name: str, payload_dir: str, remove_test: str):
    """(after install, before removal) shell scripts of a package."""
    agent = f"/usr/local/bin/{bin_name}"
    # sudo keeps DISPLAY, and the installer refuses to run inside a desktop
    post = (
        "rc=0\n"
        f"env -u DISPLAY -u XAUTHORITY bash {payload_dir}/install.sh || rc=$?\n"
        f"rm -f {payload_dir}/enroll.jws\n"
        'exit "$rc"\n'
    )
    pre = (
        f"if {remove_test} && [ -x {agent} ]; then\n"
        f"  {agent} -m uninstall || {{\n"
        '    echo "the agent refused to uninstall; set ULRMM_UNINSTALL_CODE to its'
        ' uninstall code and remove the package again" >&2\n'
        "    exit 1\n"
        "  }\n"
        "fi\n"
        "exit 0\n"
    )
    return post, pre


def _tar_gz(entries, mtime: int) -> bytes:
    """entries: (name, mode, data), data None for a directory."""
    buf = io.BytesIO()
    with tarfile.open(
        fileobj=buf, mode="w:gz", compresslevel=6, format=tarfile.GNU_FORMAT
    ) as tar:
        for name, mode, data in entries:
            info = tarfile.TarInfo(name)
            info.mode, info.mtime = mode, mtime
            info.uname = info.gname = "root"
            if data is None:
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
            else:
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _mtime(deployment) -> int:
    return int(deployment.created.timestamp())


def build_tgz(deployment, arch: str) -> bytes:
    bin_name, _, files = _payload(deployment, arch)
    top = f"{bin_name}-installer"
    entries = [(f"{top}/", 0o755, None)]
    entries += [(f"{top}/{name}", mode, data) for name, mode, data in files]
    return _tar_gz(entries, _mtime(deployment))


def _ar(members, mtime: int) -> bytes:
    out = [b"!<arch>\n"]
    for name, data in members:
        header = f"{name:<16}{mtime:<12}{0:<6}{0:<6}{0o100644:<8o}{len(data):<10}`\n"
        out += [header.encode("ascii"), data, b"\n" * (len(data) % 2)]
    return b"".join(out)


def build_deb(deployment, arch: str) -> bytes:
    bin_name, payload_dir, files = _payload(deployment, arch)
    mtime = _mtime(deployment)
    post, pre = _maint_scripts(bin_name, payload_dir, '[ "$1" = remove ]')
    vendor = _text(get_branding().company_name) or _text(brand_agent_name())
    control = (
        f"Package: {_package_name()}\n"
        f"Version: {settings.LATEST_AGENT_VER}\n"
        f"Architecture: {DEB_ARCH[arch]}\n"
        f"Maintainer: {vendor}\n"
        f"Installed-Size: {sum(len(f[2]) for f in files) // 1024 + 1}\n"
        "Depends: curl | wget, procps\n"
        "Section: admin\n"
        "Priority: optional\n"
        f"Description: {_text(brand_agent_name())} installer\n"
        " Installs the agent and enrolls it through a deployment of this server.\n"
    )
    control_tgz = _tar_gz(
        [
            ("./", 0o755, None),
            ("./control", 0o644, control.encode()),
            ("./postinst", 0o755, ("#!/bin/sh\n" + _deb_post(post)).encode()),
            ("./prerm", 0o755, ("#!/bin/sh\n" + pre).encode()),
        ],
        mtime,
    )
    rel = payload_dir.lstrip("/")
    data = [("./", 0o755, None), ("./usr/", 0o755, None), ("./usr/lib/", 0o755, None)]
    data += [(f"./{rel}/", 0o755, None)]
    data += [(f"./{rel}/{name}", mode, body) for name, mode, body in files]
    return _ar(
        [
            ("debian-binary", b"2.0\n"),
            ("control.tar.gz", control_tgz),
            ("data.tar.gz", _tar_gz(data, mtime)),
        ],
        mtime,
    )


def _deb_post(post: str) -> str:
    # dpkg also calls postinst for abort-* actions
    body = "".join(f"  {line}\n" for line in post.splitlines())
    return f'if [ "$1" = configure ]; then\n{body}fi\nexit 0\n'


# rpm header data types and the tags/flags used below (rpmtag.h, rpmds.h)
_INT16, _INT32, _STRING, _BIN, _STRARRAY, _I18N = 3, 4, 6, 7, 8, 9
_SENSE_EQUAL, _SENSE_LESS = 0x08, 0x02
_SENSE_INTERP, _SENSE_POST, _SENSE_PREUN = 0x100, 0x400, 0x800
_SENSE_RPMLIB = 0x1000000
_FILE_MISSINGOK = 0x08
_SHA256 = 8


def _rpm_header(tags: dict, region: int) -> bytes:
    """A header with an immutable region: tag -> (type, value)."""
    index, store = [], bytearray()
    for tag in sorted(tags):
        kind, value = tags[tag]
        if kind == _INT16:
            align, data = 2, struct.pack(f">{len(value)}H", *value)
        elif kind == _INT32:
            align, data = 4, struct.pack(f">{len(value)}I", *value)
        elif kind == _STRING:
            align, data, value = 1, value.encode() + b"\0", [value]
        elif kind == _BIN:
            align, data = 1, value
        else:
            align, data = 1, b"".join(v.encode() + b"\0" for v in value)
        store += bytes(-len(store) % align)
        index.append(struct.pack(">IIiI", tag, kind, len(store), len(value)))
        store += data
    count = len(index) + 1
    # the region entry points at a trailer that points back over the index
    region_entry = struct.pack(">IIiI", region, _BIN, len(store), 16)
    store += struct.pack(">IIiI", region, _BIN, -count * 16, 16)
    return (
        b"\x8e\xad\xe8\x01\0\0\0\0"
        + struct.pack(">II", count, len(store))
        + region_entry
        + b"".join(index)
        + bytes(store)
    )


def _cpio(entries, mtime: int) -> bytes:
    """newc archive of (name, mode, data, inode), plus the trailer."""
    out = bytearray()
    entries = list(entries) + [("TRAILER!!!", 0, b"", 0)]
    for name, mode, data, ino in entries:
        raw = name.encode() + b"\0"
        nlink = 2 if mode & 0o40000 else 1
        fields = (ino, mode, 0, 0, nlink, mtime if ino else 0, len(data))
        fields += (0, 0, 0, 0, len(raw), 0)
        out += b"070701" + b"".join(b"%08X" % f for f in fields) + raw
        out += bytes(-len(out) % 4) + data
        out += bytes(-len(out) % 4)
    return bytes(out)


def build_rpm(deployment, arch: str) -> bytes:
    bin_name, payload_dir, files = _payload(deployment, arch)
    mtime = _mtime(deployment)
    post, pre = _maint_scripts(bin_name, payload_dir, '[ "$1" = 0 ]')
    name = _package_name()
    version = settings.LATEST_AGENT_VER.replace("-", "~")
    release = "1"
    rpm_arch, archnum = RPM_ARCH[arch]

    paths = [(payload_dir, 0o40755, b"")]
    paths += [(f"{payload_dir}/{n}", 0o100000 | mode, d) for n, mode, d in files]
    dirnames, dirindexes, basenames = [], [], []
    for path, _, _ in paths:
        parent, base = path.rsplit("/", 1)
        if parent + "/" not in dirnames:
            dirnames.append(parent + "/")
        dirindexes.append(dirnames.index(parent + "/"))
        basenames.append(base)
    n = len(paths)
    cpio = _cpio(
        ((f".{p}", mode, d, i) for i, (p, mode, d) in enumerate(paths, 1)), mtime
    )
    payload = gzip.compress(cpio, compresslevel=6, mtime=0)
    rpmlib = _SENSE_RPMLIB | _SENSE_LESS | _SENSE_EQUAL
    requires = [
        ("/bin/sh", _SENSE_INTERP | _SENSE_POST, ""),
        ("/bin/sh", _SENSE_INTERP | _SENSE_PREUN, ""),
        ("bash", 0, ""),
        ("/usr/bin/ps", 0, ""),
        ("curl", 0, ""),
        ("rpmlib(CompressedFileNames)", rpmlib, "3.0.4-1"),
        ("rpmlib(FileDigests)", rpmlib, "4.6.0-1"),
        ("rpmlib(PayloadFilesHavePrefix)", rpmlib, "4.0-1"),
    ]
    tags = {
        100: (_STRARRAY, ["C"]),  # HEADERI18NTABLE
        1000: (_STRING, name),
        1001: (_STRING, version),
        1002: (_STRING, release),
        1004: (_I18N, [f"{_text(brand_agent_name())} installer"]),
        1005: (
            _I18N,
            ["Installs the agent and enrolls it through a deployment of this server."],
        ),
        1006: (_INT32, [mtime]),  # BUILDTIME
        1007: (_STRING, "localhost"),  # BUILDHOST
        1009: (_INT32, [sum(len(d) for _, _, d in paths)]),  # SIZE
        1011: (_STRING, _text(get_branding().company_name) or "UniversalLocal RMM"),
        1014: (_STRING, LICENSE),
        1016: (_I18N, ["Unspecified"]),  # GROUP
        1021: (_STRING, "linux"),
        1022: (_STRING, rpm_arch),
        1024: (_STRING, post),  # POSTIN
        1025: (_STRING, pre),  # PREUN
        1028: (_INT32, [len(d) for _, _, d in paths]),  # FILESIZES
        1030: (_INT16, [mode for _, mode, _ in paths]),  # FILEMODES
        1033: (_INT16, [0] * n),  # FILERDEVS
        1034: (_INT32, [mtime] * n),  # FILEMTIMES
        1035: (  # FILEDIGESTS
            _STRARRAY,
            [
                hashlib.sha256(d).hexdigest() if m & 0o100000 else ""
                for _, m, d in paths
            ],
        ),
        1036: (_STRARRAY, [""] * n),  # FILELINKTOS
        1037: (  # FILEFLAGS: the token goes after the first install
            _INT32,
            [_FILE_MISSINGOK if p.endswith("/enroll.jws") else 0 for p, _, _ in paths],
        ),
        1039: (_STRARRAY, ["root"] * n),  # FILEUSERNAME
        1040: (_STRARRAY, ["root"] * n),  # FILEGROUPNAME
        # its presence marks a binary package
        1044: (_STRING, f"{name}-{version}-{release}.src.rpm"),
        1045: (_INT32, [0xFFFFFFFF] * n),  # FILEVERIFYFLAGS
        1047: (_STRARRAY, [name]),  # PROVIDENAME
        1048: (_INT32, [r[1] for r in requires]),  # REQUIREFLAGS
        1049: (_STRARRAY, [r[0] for r in requires]),  # REQUIRENAME
        1050: (_STRARRAY, [r[2] for r in requires]),  # REQUIREVERSION
        1064: (_STRING, "4.16.1"),  # RPMVERSION
        1086: (_STRARRAY, ["/bin/sh"]),  # POSTINPROG
        1087: (_STRARRAY, ["/bin/sh"]),  # PREUNPROG
        1095: (_INT32, [1] * n),  # FILEDEVICES
        1096: (_INT32, list(range(1, n + 1))),  # FILEINODES
        1097: (_STRARRAY, [""] * n),  # FILELANGS
        1112: (_INT32, [_SENSE_EQUAL]),  # PROVIDEFLAGS
        1113: (_STRARRAY, [f"{version}-{release}"]),  # PROVIDEVERSION
        1116: (_INT32, dirindexes),
        1117: (_STRARRAY, basenames),
        1118: (_STRARRAY, dirnames),
        1124: (_STRING, "cpio"),  # PAYLOADFORMAT
        1125: (_STRING, "gzip"),  # PAYLOADCOMPRESSOR
        1126: (_STRING, "6"),  # PAYLOADFLAGS
        5011: (_INT32, [_SHA256]),  # FILEDIGESTALGO
        5062: (_STRING, "utf-8"),  # ENCODING
        5092: (_STRARRAY, [hashlib.sha256(payload).hexdigest()]),  # PAYLOADDIGEST
        5093: (_INT32, [_SHA256]),  # PAYLOADDIGESTALGO
    }
    header = _rpm_header(tags, 63)  # HEADERIMMUTABLE
    sig = _rpm_header(
        {
            273: (_STRING, hashlib.sha256(header).hexdigest()),  # SHA256
            1000: (_INT32, [len(header) + len(payload)]),  # SIZE
            1007: (_INT32, [len(cpio)]),  # PAYLOADSIZE
        },
        62,  # HEADERSIGNATURES
    )
    sig += bytes(-len(sig) % 8)
    nvr = f"{name}-{version}-{release}".encode()[:65]
    lead = struct.pack(
        ">4sBBhh66shh16s", b"\xed\xab\xee\xdb", 3, 0, 0, archnum, nvr, 1, 5, b""
    )
    return lead + sig + header + payload


BUILDERS = {
    "ps1": lambda d, arch: bootstrap_ps1(d, arch=arch).encode(),
    "deb": build_deb,
    "rpm": build_rpm,
    "tgz": build_tgz,
    "sh": lambda d, arch: bootstrap_sh(d, arch=arch).encode(),
    "sig": sh_signature,
}
