# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import base64
import datetime as dt
import gzip
import hashlib
import io
import re
import shutil
import struct
import subprocess
import tarfile
import tempfile
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from django.conf import settings
from django.test.utils import override_settings
from django.utils import timezone as djangotime
from model_bakery import baker

from clients.views import DeployDownloadThrottle
from deploy import installers, signing
from logs.models import AuditLog
from ulrmm.agent_ident import agent_artifact
from ulrmm.test import LOCMEM_CACHE, ULRMMTestCase

VER = settings.LATEST_AGENT_VER
MESH_SHA = "cd" * 32
PLACEHOLDER = re.compile(r"[A-Za-z0-9]+[Cc]hange\b|ident(Nix|Win|Svc|Artifact)")


def _pe(cert: bytes = b"", plus: bool = False) -> bytes:
    """A PE header with 16 data directories, a body, then the certificate
    table when cert is given."""
    head = bytearray(0x200)
    head[:2] = b"MZ"
    struct.pack_into("<I", head, 0x3C, 0x80)
    head[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", head, 0x80 + 20, 240 if plus else 224)
    opt = 0x80 + 24
    struct.pack_into("<H", head, opt, 0x20B if plus else 0x10B)
    dirs = opt + (112 if plus else 96)
    struct.pack_into("<I", head, dirs - 4, 16)
    body = b"\xab" * 1001
    if cert:
        struct.pack_into("<II", head, dirs + 32, len(head) + len(body), len(cert))
    return bytes(head) + body + cert


def _read_footer(data: bytes) -> str:
    # what the agent does: the block ends at the certificate table or at EOF
    cert = installers.pe_cert_entry(data[:4096])
    end = cert[1] if cert and cert[2] else len(data)
    block = data[:end].rstrip(b"\0")
    assert end - len(block) <= 7
    assert block[-8:] == b"ULRMMENR"
    size = struct.unpack("<Q", block[-16:-8])[0]
    assert 1 <= size <= 16384
    return block[-16 - size : -16].decode("ascii")


def _ar(data: bytes) -> dict:
    assert data[:8] == b"!<arch>\n"
    pos, members = 8, {}
    while pos < len(data):
        header = data[pos : pos + 60]
        assert header[58:60] == b"`\n"
        size = int(header[48:58])
        members[header[:16].decode().strip()] = data[pos + 60 : pos + 60 + size]
        pos += 60 + size + size % 2
    return members


def _tar(data: bytes) -> dict:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        return {
            m.name: (m.mode, tar.extractfile(m).read() if m.isfile() else None)
            for m in tar.getmembers()
        }


def _rpm_header(data: bytes, pos: int):
    assert data[pos : pos + 8] == b"\x8e\xad\xe8\x01\0\0\0\0"
    il, dl = struct.unpack_from(">II", data, pos + 8)
    store = data[pos + 16 + il * 16 : pos + 16 + il * 16 + dl]
    tags = {}
    for i in range(il):
        tag, kind, off, count = struct.unpack_from(">IIiI", data, pos + 16 + i * 16)
        if i == 0:
            # the region tag comes first, its trailer points back over the index
            assert (kind, count, off) == (7, 16, dl - 16)
            assert struct.unpack_from(">IIiI", store, off) == (tag, 7, -il * 16, 16)
        elif kind == 3:
            tags[tag] = list(struct.unpack_from(f">{count}H", store, off))
        elif kind == 4:
            assert off % 4 == 0
            tags[tag] = list(struct.unpack_from(f">{count}I", store, off))
        elif kind == 6:
            tags[tag] = store[off : store.index(b"\0", off)].decode()
        elif kind in (8, 9):
            tags[tag] = store[off:].split(b"\0")[:count]
            tags[tag] = [s.decode() for s in tags[tag]]
    return tags, pos + 16 + il * 16 + dl


def _cpio(data: bytes) -> dict:
    pos, files = 0, {}
    while True:
        assert data[pos : pos + 6] == b"070701"
        fields = [int(data[pos + 6 + i * 8 : pos + 14 + i * 8], 16) for i in range(13)]
        mode, size, namesize = fields[1], fields[6], fields[11]
        name = data[pos + 110 : pos + 110 + namesize - 1].decode()
        pos += 110 + namesize
        pos += -pos % 4
        if name == "TRAILER!!!":
            return files
        files[name] = (mode, data[pos : pos + size])
        pos += size
        pos += -pos % 4


def _bash_n(text: str) -> None:
    r = subprocess.run(
        ["bash", "-n"], input=text, capture_output=True, text=True, timeout=30
    )
    assert r.returncode == 0, r.stderr


class InstallerCase(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.coresettings.mesh_site = "https://mesh.example.test"
        self.coresettings.save()
        self.site = baker.make(
            "clients.Site", name="Haupt Büro", client__name="Acme & Söhne"
        )
        self.deployment = baker.make(
            "clients.Deployment",
            site=self.site,
            name="rollout",
            mon_type="workstation",
            goarch="amd64",
            expiry=djangotime.now() + dt.timedelta(days=2),
            install_flags={"power": True, "ping": False, "rdp": True},
        )
        self.dist = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dist, ignore_errors=True)
        for arch in installers.LINUX_ARCHES:
            name = agent_artifact(VER, "linux", arch)
            (self.dist / name).write_bytes(b"\x7fELF" + arch.encode() * 100)
        self.signed_exe = _pe(cert=b"\x30\x82" + b"\x11" * 70)
        (self.dist / agent_artifact(VER, "windows", "amd64")).write_bytes(
            self.signed_exe
        )
        (self.dist / agent_artifact(VER, "windows", "386")).write_bytes(_pe())
        (self.dist / signing.DIST_PUBKEY_FILE).write_text(signing.public_key_b64())
        dist = override_settings(
            AGENTS_DIST_DIR=str(self.dist),
            SELF_BUILT_AGENTS_URL="",
            CERT_FILE="/nonexistent",
            KEY_FILE="/nonexistent",
        )
        dist.enable()
        self.addCleanup(dist.disable)
        for p in (
            patch(
                "deploy.installers.get_mesh_device_id",
                new=AsyncMock(return_value="MESHID"),
            ),
            patch("deploy.installers.get_mesh_ws_url", return_value="ws://mesh"),
            patch(
                "deploy.installers.mesh_installer_sha256",
                side_effect=lambda **kw: MESH_SHA if str(kw["ident"]) == "26" else "",
            ),
        ):
            p.start()
            self.addCleanup(p.stop)
        self.jws = signing.mint_for_deployment(self.deployment)

    def sha(self, plat: str, arch: str) -> str:
        data = (self.dist / agent_artifact(VER, plat, arch)).read_bytes()
        return hashlib.sha256(data).hexdigest()


class TestFooter(InstallerCase):
    def test_roundtrip_and_alignment(self):
        for size in range(0, 9):
            block = installers.footer(self.jws, size)
            self.assertEqual((size + len(block)) % 8, 0)
            self.assertLessEqual(len(block) - len(self.jws) - 16, 7)
            self.assertEqual(_read_footer(b"x" * size + block), self.jws)

    def test_pe_certificate_table(self):
        self.assertIsNone(installers.pe_cert_entry(b"\x7fELF" + bytes(600)))
        self.assertIsNone(installers.pe_cert_entry(b"MZ" + bytes(10)))
        for plus in (False, True):
            entry, offset, size = installers.pe_cert_entry(_pe(b"C" * 24, plus=plus))
            self.assertEqual((offset, size), (0x200 + 1001, 24))
            self.assertEqual(entry, 0x80 + 24 + (112 if plus else 96) + 32)
            self.assertEqual(installers.pe_cert_entry(_pe(plus=plus))[1:], (0, 0))

    def test_signed_base_is_stripped(self):
        chunks, size, signed = installers.setup_exe(self.deployment, "amd64")
        out = b"".join(chunks)
        self.assertFalse(signed)
        self.assertEqual(len(out), size)
        image = bytearray(self.signed_exe[: 0x200 + 1001])
        entry = installers.pe_cert_entry(image)[0]
        # signature gone, the directory entry zeroed, everything else as before
        image[entry : entry + 8] = bytes(8)
        self.assertEqual(out[: len(image)], bytes(image))
        self.assertEqual(installers.pe_cert_entry(out)[1:], (0, 0))
        self.assertNotIn(b"\x30\x82\x11", out)
        self.assertEqual(_read_footer(out), self.jws)

    def test_unsigned_base_streams_original_bytes(self):
        chunks, size, signed = installers.setup_exe(self.deployment, "386")
        out = b"".join(chunks)
        base = _pe()
        self.assertEqual(out[: len(base)], base)
        self.assertEqual(len(out), size)
        self.assertEqual(_read_footer(out), self.jws)

    def test_resign_in_a_private_dir(self):
        seen = {}

        def fake_sign(cmd, **kwargs):
            src, out = cmd[cmd.index("-in") + 1], cmd[cmd.index("-out") + 1]
            seen["cmd"], seen["src"] = cmd, src
            data = Path(src).read_bytes()
            seen["input"] = data
            Path(out).write_bytes(data + b"SIGNATURE")

        signer = {"tool": "osslsigncode", "pfx": "/k.pfx", "pass_file": "/k.pass"}
        signer["ts"] = "http://ts.example.test"
        with patch.object(installers, "win_signer", return_value=signer), patch(
            "deploy.installers.subprocess.run", side_effect=fake_sign
        ):
            chunks, size, signed = installers.setup_exe(self.deployment, "amd64")
        out = b"".join(chunks)
        self.assertTrue(signed)
        self.assertEqual(out, seen["input"] + b"SIGNATURE")
        self.assertEqual(_read_footer(seen["input"]), self.jws)
        self.assertEqual(installers.pe_cert_entry(seen["input"])[1:], (0, 0))
        self.assertFalse(Path(seen["src"]).exists())
        self.assertEqual(
            seen["cmd"][1:8],
            ["sign", "-pkcs12", "/k.pfx", "-readpass", "/k.pass", "-h", "sha256"],
        )
        self.assertIn("http://ts.example.test", seen["cmd"])

    def test_failed_signing_is_unavailable(self):
        signer = {"tool": "osslsigncode", "pfx": "a", "pass_file": "b", "ts": ""}
        with patch.object(installers, "win_signer", return_value=signer), patch(
            "deploy.installers.subprocess.run",
            side_effect=subprocess.CalledProcessError(1, "osslsigncode"),
        ):
            with self.assertRaises(installers.Unavailable):
                installers.setup_exe(self.deployment, "amd64")

    def test_signer_uses_the_build_settings(self):
        pfx, pw = self.dist / "k.pfx", self.dist / "k.pass"
        pfx.write_bytes(b"x")
        pw.write_text("pw")
        with patch(
            "deploy.installers.shutil.which", return_value="/usr/bin/osslsigncode"
        ):
            self.assertIsNone(installers.win_signer())
            with override_settings(
                ULRMM_SIGN_WIN_PFX=str(pfx), ULRMM_SIGN_WIN_PASS_FILE=str(pw)
            ):
                self.assertEqual(installers.win_signer()["pfx"], str(pfx))
            with override_settings(
                ULRMM_SIGN_WIN_PFX="/missing.pfx", ULRMM_SIGN_WIN_PASS_FILE=str(pw)
            ):
                self.assertIsNone(installers.win_signer())
        with patch("deploy.installers.shutil.which", return_value=None):
            with override_settings(
                ULRMM_SIGN_WIN_PFX=str(pfx), ULRMM_SIGN_WIN_PASS_FILE=str(pw)
            ):
                self.assertIsNone(installers.win_signer())


class TestScripts(InstallerCase):
    def test_single_arch_enrollment_script(self):
        text = installers.bootstrap_sh(self.deployment, arch="arm64")
        self.assertIn(f"enrollJWS='{self.jws}'", text)
        self.assertIn(f"agentSha256='{self.sha('linux', 'arm64')}'", text)
        self.assertRegex(
            text,
            rf"agentDL='https://[^']+/agentdist/{agent_artifact(VER, 'linux', 'arm64')}'",
        )
        self.assertIn(
            "meshDL='https://mesh.example.test/meshagents?id=MESHID&installflags=2&meshinstall=26'",
            text,
        )
        self.assertIn(f"meshSha256='{MESH_SHA}'", text)
        self.assertIn(
            'fetch_binary "mesh agent" "$meshDL" "$meshTmp" "$meshSha256"', text
        )
        self.assertIn("agentBuilds=''", text)
        self.assertIn("localBinary=''", text)
        self.assertIn("token=''", text)
        self.assertIsNone(PLACEHOLDER.search(text))
        _bash_n(text)

    def test_multi_arch_script_picks_by_uname(self):
        (self.dist / agent_artifact(VER, "linux", "386")).unlink()
        text = installers.bootstrap_sh(self.deployment)
        builds = re.search(r"^agentBuilds='(.*?)'$", text, re.S | re.M).group(1)
        lines = [line.split(" ") for line in builds.splitlines()]
        self.assertEqual([line[0] for line in lines], ["amd64", "arm64", "arm"])
        self.assertEqual(lines[2][2], self.sha("linux", "arm"))
        self.assertTrue(lines[0][3].endswith("meshinstall=6"))
        # MeshCentral gave no hash for amd64: four columns, no check
        self.assertEqual([len(line) for line in lines], [4, 5, 4])
        self.assertEqual(lines[1][4], MESH_SHA)
        self.assertIn("agentDL=''", text)
        _bash_n(text)

        block = re.search(
            r'^if \[ -n "\$agentBuilds" \]; then\n.*?^fi\n', text, re.S | re.M
        )
        prelude = re.search(r"^agentBuilds=.*?'$", text, re.S | re.M).group(0)
        for machine, expect in (
            ("x86_64", "amd64"),
            ("aarch64", "arm64"),
            ("armv7l", "arm"),
            ("i686", None),
            ("riscv64", None),
        ):
            runner = (
                f'uname() {{ echo {machine}; }}\ndie() {{ echo "DIE $*"; exit 1; }}\n'
                f"agentDL=''\n{prelude}\n{block.group(0)}"
                'echo "$agentDL $agentSha256 $meshDL ${meshSha256:--}"\n'
            )
            r = subprocess.run(
                ["bash", "-c", runner], capture_output=True, text=True, timeout=30
            )
            if expect is None:
                self.assertEqual(r.returncode, 1, machine)
                self.assertIn("DIE", r.stdout)
                continue
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            url, sha, mesh, mesh_sha = r.stdout.split()
            self.assertEqual(mesh_sha, MESH_SHA if expect == "arm64" else "-")
            self.assertTrue(url.endswith(agent_artifact(VER, "linux", expect)), machine)
            self.assertEqual(sha, self.sha("linux", expect))
            self.assertIn("meshinstall=", mesh)

    def test_local_binary_script_has_no_token(self):
        text = installers.bootstrap_sh(self.deployment, arch="amd64", local_binary=True)
        self.assertIn("localBinary='true'", text)
        self.assertIn("enrollJWS=''", text)
        self.assertNotIn(self.jws, text)
        self.assertIn('install -m 0755 "${here}/ulrmm-agent" "$agentNew"', text)
        _bash_n(text)
        with self.assertRaises(ValueError):
            installers.bootstrap_sh(self.deployment, local_binary=True)

    def test_missing_builds(self):
        for arch in installers.LINUX_ARCHES:
            (self.dist / agent_artifact(VER, "linux", arch)).unlink()
        with self.assertRaises(installers.Unavailable):
            installers.bootstrap_sh(self.deployment)
        with self.assertRaises(installers.Unavailable):
            installers.bootstrap_sh(self.deployment, arch="amd64")

    def test_signature_of_the_sh_body(self):
        body = installers.bootstrap_sh(self.deployment).encode()
        sig = installers.sh_signature(self.deployment)
        self.assertEqual(sig, installers.sh_signature(self.deployment))
        key = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(signing.public_key_b64())
        )
        key.verify(base64.b64decode(sig), body)

    def test_powershell_bootstrap(self):
        text = installers.bootstrap_ps1(self.deployment, arch="386")
        self.assertIsNone(PLACEHOLDER.search(text))
        self.assertIn(f"$enroll = '{self.jws}'", text)
        self.assertIn(f"$sha256 = '{self.sha('windows', '386')}'", text)
        self.assertIn(f"$innosetup = '{agent_artifact(VER, 'windows', '386')}'", text)
        self.assertIn("$power = 1", text)
        self.assertIn("$auth = ''", text)
        self.assertIn("'-enroll', \"`\"$enrollFile`\"\", '-silent'", text)
        self.assertIn("Get-FileHash -Algorithm SHA256", text)
        self.assertIn("C:\\Program Files\\ULRMM Agent\\ulrmm-agent.exe", text)
        with self.assertRaises(ValueError):
            installers.bootstrap_ps1(self.deployment, arch="arm64")
        (self.dist / agent_artifact(VER, "windows", "386")).unlink()
        with self.assertRaises(installers.Unavailable):
            installers.bootstrap_ps1(self.deployment, arch="386")


class TestPackages(InstallerCase):
    prefix = "usr/lib/ulrmm-agent-installer"

    def test_deb(self):
        members = _ar(installers.build_deb(self.deployment, "arm"))
        self.assertEqual(
            list(members), ["debian-binary", "control.tar.gz", "data.tar.gz"]
        )
        self.assertEqual(members["debian-binary"], b"2.0\n")
        control = _tar(members["control.tar.gz"])
        fields = dict(
            line.split(": ", 1)
            for line in control["./control"][1].decode().splitlines()
            if not line.startswith(" ")
        )
        self.assertEqual(fields["Package"], "ulrmm-agent")
        self.assertEqual(fields["Version"], VER)
        self.assertEqual(fields["Architecture"], "armhf")
        self.assertEqual(fields["Depends"], "curl | wget, procps")
        postinst, prerm = control["./postinst"], control["./prerm"]
        self.assertEqual((postinst[0], prerm[0]), (0o755, 0o755))
        self.assertIn(f"bash /{self.prefix}/install.sh", postinst[1].decode())
        self.assertIn(f"rm -f /{self.prefix}/enroll.jws", postinst[1].decode())
        self.assertIn('[ "$1" = configure ]', postinst[1].decode())
        self.assertIn('[ "$1" = remove ]', prerm[1].decode())
        self.assertIn("/usr/local/bin/ulrmm-agent -m uninstall", prerm[1].decode())
        for script in (postinst[1], prerm[1]):
            r = subprocess.run(
                ["sh", "-n"], input=script, capture_output=True, timeout=30
            )
            self.assertEqual(r.returncode, 0, r.stderr)

        data = _tar(members["data.tar.gz"])
        binary = (self.dist / agent_artifact(VER, "linux", "arm")).read_bytes()
        self.assertEqual(data[f"./{self.prefix}/ulrmm-agent"], (0o755, binary))
        self.assertEqual(
            data[f"./{self.prefix}/enroll.jws"], (0o600, f"{self.jws}\n".encode())
        )
        mode, script = data[f"./{self.prefix}/install.sh"]
        self.assertEqual(mode, 0o755)
        self.assertIn("localBinary='true'", script.decode())
        self.assertIn(f"agentSha256='{self.sha('linux', 'arm')}'", script.decode())
        self.assertNotIn(self.jws.encode(), script)
        _bash_n(script.decode())

    def test_rpm(self):
        data = installers.build_rpm(self.deployment, "arm64")
        magic, major, _, kind, archnum, name, osnum, sigtype = struct.unpack_from(
            ">4sBBhh66shh", data
        )
        self.assertEqual(
            (magic, major, kind, archnum, osnum, sigtype),
            (b"\xed\xab\xee\xdb", 3, 0, 19, 1, 5),
        )
        self.assertEqual(name.rstrip(b"\0").decode(), f"ulrmm-agent-{VER}-1")
        sig, pos = _rpm_header(data, 96)
        pos += -pos % 8
        tags, end = _rpm_header(data, pos)
        header, payload = data[pos:end], data[end:]
        cpio = gzip.decompress(payload)
        self.assertEqual(sig[273], hashlib.sha256(header).hexdigest())
        self.assertEqual(sig[1000], [len(header) + len(payload)])
        self.assertEqual(sig[1007], [len(cpio)])
        self.assertEqual(tags[5092], [hashlib.sha256(payload).hexdigest()])
        self.assertEqual((tags[5093], tags[5011]), ([8], [8]))
        self.assertEqual(
            (tags[1000], tags[1001], tags[1002]), ("ulrmm-agent", VER, "1")
        )
        self.assertEqual(tags[1022], "aarch64")
        self.assertEqual(tags[1044], f"ulrmm-agent-{VER}-1.src.rpm")
        self.assertIn(f"bash /{self.prefix}/install.sh", tags[1024])
        self.assertIn('[ "$1" = 0 ]', tags[1025])
        self.assertIn("-m uninstall", tags[1025])
        self.assertEqual(tags[1118], ["/usr/lib/", f"/{self.prefix}/"])
        self.assertEqual(
            tags[1117],
            ["ulrmm-agent-installer", "enroll.jws", "install.sh", "ulrmm-agent"],
        )
        self.assertEqual(tags[1116], [0, 1, 1, 1])
        self.assertEqual(tags[1030], [0o40755, 0o100600, 0o100755, 0o100755])

        files = _cpio(cpio)
        self.assertEqual(
            list(files),
            [f"./{self.prefix}"] + [f"./{self.prefix}/{b}" for b in tags[1117][1:]],
        )
        for path, digest, size, mode in zip(files, tags[1035], tags[1028], tags[1030]):
            self.assertEqual(files[path][0], mode)
            self.assertEqual(len(files[path][1]), size)
            if mode & 0o100000:
                self.assertEqual(hashlib.sha256(files[path][1]).hexdigest(), digest)
        self.assertEqual(
            files[f"./{self.prefix}/enroll.jws"][1], f"{self.jws}\n".encode()
        )
        binary = (self.dist / agent_artifact(VER, "linux", "arm64")).read_bytes()
        self.assertEqual(files[f"./{self.prefix}/ulrmm-agent"][1], binary)
        self.assertEqual(tags[1009], [sum(tags[1028])])

    def test_tgz(self):
        members = _tar(installers.build_tgz(self.deployment, "386"))
        top = "ulrmm-agent-installer"
        self.assertEqual(
            sorted(members),
            [f"{top}", f"{top}/enroll.jws", f"{top}/install.sh", f"{top}/ulrmm-agent"],
        )
        self.assertEqual(members[f"{top}/enroll.jws"][0], 0o600)
        self.assertEqual(members[f"{top}/ulrmm-agent"][0], 0o755)
        self.assertIn("localBinary='true'", members[f"{top}/install.sh"][1].decode())

    def test_download_name(self):
        self.assertEqual(
            installers.download_name(self.deployment, "tgz", "386"),
            "UniversalLocal-RMM-Acme-Sohne-Haupt-Buro-386.tar.gz",
        )
        self.assertEqual(
            installers.download_name(self.deployment, "sig"),
            "UniversalLocal-RMM-Acme-Sohne-Haupt-Buro.sh.sig",
        )


class TestDeployLink(InstallerCase):
    def setUp(self):
        super().setUp()
        self.setup_client()
        # no authentication runs, so a bad header is no 401
        self.client.credentials(HTTP_AUTHORIZATION="Token not-a-token")
        self.ip = f"10.{uuid.uuid4().int % 250}.{uuid.uuid4().int % 250}.7"

    def get(self, fmt=None, arch=None, uid=None):
        query = {k: v for k, v in (("fmt", fmt), ("arch", arch)) if v}
        uid = uid or self.deployment.uid
        return self.client.get(f"/clients/{uid}/deploy/", query, REMOTE_ADDR=self.ip)

    def body(self, r) -> bytes:
        return b"".join(r.streaming_content) if r.streaming else r.content

    def test_codes(self):
        self.assertEqual(self.get(uid=uuid.uuid4()).status_code, 404)
        self.assertEqual(self.get(uid="abc123").status_code, 404)
        self.assertEqual(self.get(fmt="zip").status_code, 400)
        self.assertEqual(self.get(fmt="exe", arch="arm64").status_code, 400)
        self.assertEqual(self.get(fmt="deb", arch="sparc").status_code, 400)
        (self.dist / agent_artifact(VER, "linux", "arm")).unlink()
        r = self.get(fmt="rpm", arch="arm")
        self.assertEqual(r.status_code, 503)
        self.assertIn("update.sh", r.data)
        (self.dist / signing.DIST_PUBKEY_FILE).write_text(
            base64.b64encode(b"o" * 32).decode()
        )
        self.assertEqual(self.get(fmt="sh").status_code, 503)
        self.deployment.expiry = djangotime.now() - dt.timedelta(minutes=1)
        self.deployment.save()
        self.assertEqual(self.get(fmt="sh").status_code, 410)
        self.assertFalse(AuditLog.objects.exists())

    def test_exe_download(self):
        r = self.get()
        self.assertEqual(r.status_code, 200)
        out = self.body(r)
        self.assertEqual(int(r["Content-Length"]), len(out))
        self.assertEqual(r["X-ULRMM-Unsigned"], "1")
        self.assertEqual(r["Cache-Control"], "no-store")
        self.assertEqual(
            r["Content-Disposition"],
            'attachment; filename="UniversalLocal-RMM-Acme-Sohne-Haupt-Buro-amd64.exe"',
        )
        self.assertEqual(_read_footer(out), self.jws)

        audit = AuditLog.objects.get()
        self.assertEqual(
            (audit.username, audit.action, audit.object_type),
            ("anonymous", "agent_install", "site"),
        )
        self.assertEqual(
            audit.after_value,
            {
                "deployment": self.deployment.pk,
                "fmt": "exe",
                "arch": "amd64",
                "signed": False,
            },
        )
        self.assertEqual(audit.debug_info, {"ip": self.ip})
        self.assertNotIn(self.jws, str(audit.__dict__))
        # audit readers must not get the link
        self.assertNotIn(str(self.deployment.uid), str(audit.__dict__))
        self.deployment.name = ""
        self.deployment.save()
        self.get(fmt="sh")
        audit = AuditLog.objects.latest("pk")
        self.assertIn(f"deployment #{self.deployment.pk} for", audit.message)
        self.assertNotIn(str(self.deployment.uid), str(audit.__dict__))

    def test_every_format(self):
        for fmt, arch, ctype in (
            ("ps1", "amd64", "text/plain"),
            ("deb", "amd64", "application/vnd.debian.binary-package"),
            ("rpm", "386", "application/x-rpm"),
            ("tgz", "arm64", "application/gzip"),
            ("sh", "arm", "text/x-shellscript"),
        ):
            r = self.get(fmt=fmt, arch=arch)
            self.assertEqual(r.status_code, 200, (fmt, r.content[:200]))
            self.assertTrue(r["Content-Type"].startswith(ctype), fmt)
            self.assertTrue(
                r["Content-Disposition"].endswith(
                    f'-{arch}.{installers.EXTENSIONS[fmt]}"'
                )
            )
            self.assertNotIn("X-ULRMM-Unsigned", r)
        self.assertEqual(AuditLog.objects.count(), 5)

    def test_sh_and_sig(self):
        r = self.get(fmt="sh")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"agentBuilds='amd64 ", r.content)
        self.assertTrue(r["Content-Disposition"].endswith('Haupt-Buro.sh"'))
        sig = self.get(fmt="sig")
        self.assertEqual(sig.status_code, 200)
        key = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(signing.public_key_b64())
        )
        key.verify(base64.b64decode(sig.content), r.content)

    def test_throttled_per_ip(self):
        with override_settings(CACHES=LOCMEM_CACHE), patch.object(
            DeployDownloadThrottle, "rate", "2/hour", create=True
        ):
            codes = [self.get(fmt="sh").status_code for _ in range(3)]
            self.ip = "10.255.255.1"
            other = self.get(fmt="sh").status_code
        self.assertEqual(codes, [200, 200, 429])
        self.assertEqual(other, 200)

    def test_throttled_per_ip_and_deployment(self):
        other = baker.make(
            "clients.Deployment",
            site=self.deployment.site,
            expiry=self.deployment.expiry,
            mon_type="server",
            goarch="amd64",
        )
        with override_settings(CACHES=LOCMEM_CACHE), patch.object(
            DeployDownloadThrottle, "rate", "2/hour", create=True
        ):
            codes = [self.get(fmt="sig").status_code for _ in range(3)]
            # a second rollout from the same address has its own count
            codes += [self.get(fmt="sig", uid=other.uid).status_code for _ in range(2)]
            # unknown links share the address's count
            codes += [self.get(uid=uuid.uuid4()).status_code for _ in range(3)]
        self.assertEqual(codes, [200, 200, 429, 200, 200, 404, 404, 429])
        # a site behind one NAT address installs a few hundred hosts an hour
        self.assertGreaterEqual(DeployDownloadThrottle().num_requests, 600)
