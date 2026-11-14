# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Parts of install_lib.sh and restore.sh run on their own, sudo is a stand-in
that runs the command."""

import grp
import os
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
LIB = REPO / "riddix" / "scripts" / "install_lib.sh"
RESTORE = REPO / "restore.sh"


def function(path: Path, name: str) -> str:
    return re.search(
        rf"^{name}\(\) [{{(]\n.*?^[}})]\n", path.read_text(), re.S | re.M
    ).group(0)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        shim = self.root / "bin"
        shim.mkdir()
        (shim / "sudo").write_text('#!/bin/sh\nexec "$@"\n')
        (shim / "sudo").chmod(0o755)
        self.env = dict(os.environ, PATH=f"{shim}:{os.environ['PATH']}")

    def bash(self, script, *args, **env):
        return subprocess.run(
            ["bash", "-c", 'lib_die() { echo "DIE $*"; exit 1; }\n' + script]
            + ["bash", *args],
            env=dict(self.env, **env),
            capture_output=True,
            text=True,
            timeout=60,
        )


@unittest.skipUnless(os.geteuid() == 0, "chown needs root")
class TestLetsencryptPerms(Base):
    def test_root_owns_the_tree_the_group_reads_the_keys(self):
        le = self.root / "le"
        arch, live = le / "archive" / "ex.com", le / "live" / "ex.com"
        hooks = le / "renewal-hooks" / "deploy"
        for d in (arch, live, hooks):
            d.mkdir(parents=True)
        for d in (le / "archive", le / "live"):
            d.chmod(0o700)
        (arch / "privkey1.pem").write_text("key")
        (arch / "privkey1.pem").chmod(0o600)
        (arch / "fullchain1.pem").write_text("cert")
        (arch / "fullchain1.pem").chmod(0o644)
        (live / "privkey.pem").symlink_to("../../archive/ex.com/privkey1.pem")
        (hooks / "planted.sh").write_text("#!/bin/sh\n")
        for p in le.rglob("*"):
            os.lchown(p, 65534, 65534)

        for _ in range(2):  # update.sh runs it on every update
            r = self.bash(
                function(LIB, "letsencrypt_perms") + 'letsencrypt_perms "$1" "$2"',
                str(le),
                "daemon",
            )
            self.assertEqual(r.returncode, 0, r.stderr)

        gid = grp.getgrnam("daemon").gr_gid
        for p in [le, *le.rglob("*")]:
            st = os.lstat(p)
            self.assertEqual(st.st_uid, 0, p)
            rel = p.relative_to(le).parts
            want = gid if rel and rel[0] in ("live", "archive") else 0
            self.assertEqual(st.st_gid, want, p)
        mode = lambda p: stat.S_IMODE(os.stat(p).st_mode)  # noqa: E731
        self.assertEqual(mode(arch / "privkey1.pem"), 0o640)
        self.assertEqual(mode(arch / "fullchain1.pem"), 0o644)
        self.assertEqual(mode(le / "live"), 0o751)
        self.assertEqual(mode(le / "archive"), 0o751)

    def test_own_key_outside_live_and_archive_keeps_the_tree(self):
        le = self.root / "le"
        mine = le / "mine"
        mine.mkdir(parents=True)
        (mine / "key.pem").write_text("key")
        (mine / "key.pem").chmod(0o600)
        os.chown(mine / "key.pem", 65534, 65534)
        r = self.bash(
            'lib_warn() { echo "$*" >&2; }\n'
            + function(LIB, "letsencrypt_perms")
            + 'letsencrypt_perms "$1" daemon "$1/mine/key.pem"',
            str(le),
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("outside live/ and archive/", r.stderr)
        self.assertEqual(os.stat(mine / "key.pem").st_uid, 65534)

    def test_missing_directory_is_left_alone(self):
        r = self.bash(
            function(LIB, "letsencrypt_perms") + 'letsencrypt_perms "$1" daemon',
            str(self.root / "none"),
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse((self.root / "none").exists())


@unittest.skipUnless(shutil.which("gpg"), "needs gpg")
class TestFetchAptKey(Base):
    def setUp(self):
        super().setUp()
        home = self.root / "gnupg"
        home.mkdir(mode=0o700)
        self.env["GNUPGHOME"] = str(home)
        self.fprs = []
        for name in ("one", "two"):
            subprocess.run(
                ["gpg", "--batch", "--passphrase", "", "--quick-gen-key", name]
                + ["ed25519", "sign", "never"],
                env=self.env,
                check=True,
                capture_output=True,
            )
            out = subprocess.run(
                ["gpg", "--with-colons", "--fingerprint", name],
                env=self.env,
                check=True,
                capture_output=True,
                text=True,
            ).stdout
            self.fprs.append(re.search(r"^fpr:+([0-9A-F]+):", out, re.M).group(1))

    def fetch(self, names, allowed):
        served = self.root / "served.asc"
        served.write_bytes(
            subprocess.run(
                ["gpg", "--armor", "--export", *names],
                env=self.env,
                check=True,
                capture_output=True,
            ).stdout
        )
        ring = self.root / "ring.gpg"
        ring.unlink(missing_ok=True)
        curl = 'curl() { while [ $# -gt 1 ]; do [ "$1" = -o ] && o=$2; shift; done; cp "$SERVED" "$o"; }\n'
        r = self.bash(
            'lib_warn() { echo "$*" >&2; }\n'
            + curl
            + function(LIB, "fetch_apt_key")
            + 'fetch_apt_key https://example.invalid/key "$1" "$2"',
            allowed,
            str(ring),
            SERVED=str(served),
        )
        return r.returncode, ring.exists()

    def test_only_the_pinned_keys_are_written(self):
        one, two = self.fprs
        self.assertEqual(self.fetch(["one"], one), (0, True))
        self.assertEqual(self.fetch(["one", "two"], f"{two} {one}"), (0, True))
        self.assertEqual(self.fetch(["one"], two), (1, False))
        # a key slipped in next to the real one
        self.assertEqual(self.fetch(["one", "two"], one), (1, False))
        self.assertEqual(self.fetch([], one), (1, False))


class TestPgCreateDb(Base):
    def test_database_and_role_only_when_missing(self):
        r = self.bash(
            "sudo() { cat; }\n"
            + function(LIB, "pg_create_db")
            + "pg_create_db db1 role1 pw1",
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        sql = r.stdout
        self.assertNotRegex(sql, r"(?m)^CREATE ")
        self.assertIn(
            "WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'db1')\\gexec",
            sql,
        )
        self.assertIn(
            "WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'role1')\\gexec",
            sql,
        )
        self.assertIn("ALTER USER role1 WITH PASSWORD 'pw1';", sql)


class TestBuildAgentsStep(Base):
    # only builtins and these functions: a makensis on this host must not count
    STUBS = (
        'PATH="$NOPATH"\n'
        'lib_info() { echo "$*" >&2; }\n'
        'lib_warn() { echo "$*" >&2; }\n'
        'sudo() { "$@"; }\n'
        "mkdir() { :; }\n"
        "chown() { :; }\n"
        'uname() { echo "$UNAME_M"; }\n'
        'ls_get() { case $1 in ULRMM_WIN_PACKER) printf %s "$LS_PACKER" ;;\n'
        '  ULRMM_SIGN_WIN_PFX) printf %s "$LS_PFX" ;; esac; return 0; }\n'
        'env() { echo "ENV $1"; shift; "$@"; }\n'
        'apt-get() { echo "APT $*"; case " $* " in\n'
        '  *" update "*) [ "$UPDATE_OK" = 1 ]; return ;;\n'
        '  *" nsis "*) [ "$APT_OK" = 1 ] || return 1; makensis() { :; } ;;\n'
        '  *" osslsigncode "*) [ "$OSSL_OK" = 1 ] || return 1; osslsigncode() { :; } ;;\n'
        "esac; }\n"
        'bash() { echo "BUILD $*"; }\n'
    )
    APT = "APT -o DPkg::Lock::Timeout=300"

    def step(
        self,
        windows_in_dist=False,
        apt_ok=False,
        update_ok=None,
        ossl_ok=True,
        have="",
        uname="x86_64",
        **env,
    ):
        root = self.root / "agents"
        (root / "dist").mkdir(parents=True, exist_ok=True)
        (root / "dist" / "ulrmm-agent-v1.13.11.2026-linux-amd64").write_text("x")
        if windows_in_dist:
            (root / "dist" / "ulrmm-agent-v1.13.11.2026-windows-amd64.exe").write_text(
                "x"
            )
        (self.root / "nopath").mkdir(exist_ok=True)
        # tools already on the host
        present = "".join(f"{t}() {{ :; }}\n" for t in have.split())
        return self.bash(
            self.STUBS
            + present
            + function(LIB, "build_agents_step")
            + "build_agents_step",
            AGENT_ROOT=str(root),
            NOPATH=str(self.root / "nopath"),
            APT_OK="1" if apt_ok else "0",
            UPDATE_OK="1" if (apt_ok if update_ok is None else update_ok) else "0",
            OSSL_OK="1" if ossl_ok else "0",
            UNAME_M=uname,
            USER="u",
            LS_PACKER=env.pop("LS_PACKER", ""),
            LS_PFX=env.pop("LS_PFX", ""),
            ULRMM_SIGN_WIN_PFX=env.pop("ULRMM_SIGN_WIN_PFX", ""),
            **env,
        )

    def test_nsis_is_installed_on_every_architecture(self):
        for arch in ("x86_64", "aarch64"):
            with self.subTest(arch=arch):
                r = self.step(apt_ok=True, uname=arch)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertIn(f"{self.APT} update -qq", r.stdout)
                self.assertIn(f"{self.APT} install -y -qq nsis\n", r.stdout)
                self.assertIn(f"{self.APT} install -y -qq osslsigncode", r.stdout)
                # every apt-get call runs without questions
                self.assertEqual(
                    r.stdout.count("ENV DEBIAN_FRONTEND=noninteractive"),
                    r.stdout.count("APT "),
                )
                self.assertIn("BUILD /rmm/riddix/agents/build_agents.sh", r.stdout)
                self.assertEqual(r.stderr.count("WARNING"), 0, r.stderr)

    def test_failed_update_still_installs_nsis(self):
        r = self.step(windows_in_dist=True, apt_ok=True, update_ok=False)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("WARNING: apt-get update failed", r.stderr)
        self.assertIn(f"{self.APT} install -y -qq nsis\n", r.stdout)
        self.assertNotIn("makensis is missing", r.stderr)
        self.assertIn("BUILD /rmm/riddix/agents/build_agents.sh", r.stdout)

    def test_osslsigncode_is_optional(self):
        r = self.step(windows_in_dist=True, apt_ok=True, ossl_ok=False)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stderr.count("WARNING"), 1, r.stderr)
        self.assertIn("WARNING: osslsigncode could not be installed", r.stderr)
        self.assertIn("BUILD /rmm/riddix/agents/build_agents.sh", r.stdout)

    def test_only_the_missing_tool_is_installed(self):
        # without signing a missing osslsigncode alone runs no apt
        r = self.step(have="makensis")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("APT", r.stdout)
        self.assertEqual(r.stderr, "Building agents (this can take a few minutes)...\n")
        self.assertIn("BUILD", r.stdout)
        for env in ({"ULRMM_SIGN_WIN_PFX": "/k.pfx"}, {"LS_PFX": "/k.pfx"}):
            with self.subTest(**env):
                r = self.step(have="makensis", **env)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertNotIn("install -y -qq nsis", r.stdout)
                self.assertIn(f"{self.APT} install -y -qq osslsigncode", r.stdout)
                r = self.step(have="makensis osslsigncode", **env)
                self.assertNotIn("APT", r.stdout)
        r = self.step(windows_in_dist=True, have="osslsigncode", apt_ok=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(f"{self.APT} install -y -qq nsis\n", r.stdout)
        self.assertNotIn("install -y -qq osslsigncode", r.stdout)
        r = self.step(have="makensis osslsigncode")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("APT", r.stdout)
        self.assertIn("BUILD", r.stdout)

    def test_info_line_names_what_is_installed(self):
        info = "Installing {} for the Windows installer..."
        for have, env, tools in (
            ("", {}, "nsis and osslsigncode"),
            ("osslsigncode", {}, "nsis"),
            ("makensis", {"ULRMM_SIGN_WIN_PFX": "/k.pfx"}, "osslsigncode"),
        ):
            with self.subTest(have=have):
                r = self.step(apt_ok=True, have=have, **env)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertIn(info.format(tools) + "\n", r.stderr)
                self.assertEqual(r.stderr.count("Installing"), 1, r.stderr)

    def test_missing_makensis_fails_where_windows_agents_were_published(self):
        r = self.step(windows_in_dist=True)
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("WARNING: nsis could not be installed.", r.stderr)
        self.assertIn("ERROR: makensis is missing", r.stderr)
        self.assertNotIn("ULRMM_WIN_PACKER", r.stderr)
        self.assertNotIn("BUILD", r.stdout)
        # the fallback packer is named where it is already installed
        r = self.step(windows_in_dist=True, have="iscc")
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn('ULRMM_WIN_PACKER = "inno" in local_settings.py', r.stderr)
        self.assertNotIn("BUILD", r.stdout)

    def test_missing_makensis_warns_on_a_host_without_windows_agents(self):
        r = self.step()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("WARNING: makensis is missing", r.stderr)
        self.assertIn("BUILD", r.stdout)

    def test_inno_fallback_installs_nothing(self):
        for env in ({"ULRMM_WIN_PACKER": "inno"}, {"LS_PACKER": "inno"}):
            with self.subTest(**env):
                r = self.step(windows_in_dist=True, **env)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertNotIn("APT", r.stdout)
                self.assertIn("BUILD", r.stdout)


@unittest.skipUnless(shutil.which("git"), "needs git")
class TestCloneOrFetch(Base):
    def git(self, *args):
        subprocess.run(["git", *args], check=True, capture_output=True, env=self.env)

    def test_second_run_moves_the_clone_to_the_branch(self):
        src, dest = self.root / "src", self.root / "dest"
        self.env.update(
            GIT_AUTHOR_NAME="t",
            GIT_AUTHOR_EMAIL="t@t",
            GIT_COMMITTER_NAME="t",
            GIT_COMMITTER_EMAIL="t@t",
        )
        self.git("init", "-q", "-b", "main", str(src))
        self.git("-C", str(src), "commit", "-q", "--allow-empty", "-m", "a")
        script = (
            function(LIB, "url_host")
            + function(LIB, "git_auth")
            + function(LIB, "clone_or_fetch")
            + 'clone_or_fetch "$1" main "$2" && git -C "$2" rev-parse HEAD'
        )
        first = self.bash(script, str(src), str(dest), GIT_URL=str(src))
        self.assertEqual(first.returncode, 0, first.stderr)
        self.git("-C", str(src), "commit", "-q", "--allow-empty", "-m", "b")
        (dest / "left.txt").write_text("untracked")
        second = self.bash(script, str(src), str(dest), GIT_URL=str(src))
        self.assertEqual(second.returncode, 0, second.stderr)
        head = subprocess.run(
            ["git", "-C", str(src), "rev-parse", "HEAD"], capture_output=True, text=True
        ).stdout
        self.assertEqual(second.stdout, head)
        self.assertNotEqual(first.stdout, head)


class TestTexts(Base):
    def render(self, call):
        r = self.bash(f'. "{LIB}"\n{call}')
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout

    def test_anonymous_posts_get_a_small_body_cap(self):
        conf = self.render(
            "rmm_nginx_conf api.example.com rmm.example.com /c/cert.pem /c/key.pem"
        )
        self.assertIn("\n    client_max_body_size 300M;\n", conf)
        blocks = re.findall(
            r"^    location ~ (\S+) \{\n(.*?)^    \}\n", conf, re.S | re.M
        )
        capped = [(p, b) for p, b in blocks if "client_max_body_size 64k;" in b]
        self.assertEqual(len(capped), 1, blocks)
        pattern, body = capped[0]
        self.assertIn("        uwsgi_pass  ulrmm;\n", body)
        agent = "aB3_-" * 8
        for uri in (
            "/v2/login/",
            "/v2/checkcreds/",
            "/_allauth/browser/v1/auth/provider/redirect/",
            "/accounts/oidc/1/login/callback/",
            "/core/status/",
            "/core/v2/status/",
            f"/api/v3/{agent}/token/grant/",
            f"/api/v3/{agent}/token/refresh/",
            f"/api/v3/{agent}/recover/",
        ):
            self.assertTrue(re.search(pattern, uri), uri)
        for uri in (
            "/api/v3/newagent/",
            "/api/v3/software/",
            f"/api/v3/{agent}/config/",
            "/scripts/upload/",
            "/accounts/users/",
        ):
            self.assertFalse(re.search(pattern, uri), uri)

    def test_logrotate_takes_the_django_debug_logs(self):
        text = self.render("logrotate_text")
        m = re.search(
            r"^(\S.*) \{\n(.*?)^\}\n", text.split("/var/log/celery", 1)[1], re.S | re.M
        )
        self.assertIn("/rmm/api/ulrmm/ulrmm/private/log/*_debug.log", m.group(1))
        self.assertIn("    copytruncate\n", m.group(2))


class TestRestore(Base):
    def test_unpack_refuses_links(self):
        for name, link in (("plain", False), ("linked", True)):
            src = self.root / f"{name}-src"
            (src / "certs" / "custom").mkdir(parents=True)
            (src / "certs" / "custom" / "cert").write_text("c")
            if link:
                (src / "certs" / "custom" / "key").symlink_to("/etc/shadow")
            archive = self.root / f"{name}.tar"
            with tarfile.open(archive, "w") as tar:
                tar.add(src, arcname=".")
            out = self.root / f"{name}-out"
            out.mkdir()
            r = self.bash(
                function(RESTORE, "unpack_backup") + 'unpack_backup "$1" "$2"',
                str(archive),
                str(out),
            )
            if link:
                self.assertEqual(r.returncode, 1)
                self.assertIn("has links or special files", r.stdout)
            else:
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_loaded_database_is_kept_only_with_resume(self):
        psql = 'psql() { if [ "$1" = -tA ]; then echo 1; else echo LOADED >&2; fi; }\ngzip() { :; }\nlib_info() { :; }\n'
        script = psql + function(RESTORE, "load_dump") + "load_dump dump db role pw"
        r = self.bash(script, resume="false")
        self.assertEqual(r.returncode, 1)
        self.assertIn("already has tables", r.stdout)
        r = self.bash(script, resume="true")
        self.assertEqual((r.returncode, r.stdout), (0, ""))
        self.assertNotIn("LOADED", r.stderr)
        r = self.bash(script.replace("echo 1;", ":;"), resume="false")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("LOADED", r.stderr)

    def test_restored_domains_must_be_host_names(self):
        text = RESTORE.read_text()
        start = text.index("for v in API FRONTEND MESHDOMAIN; do\n")
        loop = text[start : text.index("\ndone\n", start) + 6]
        valid = re.search(r"^valid_name\(\) .*\n", text, re.M).group(0)
        script = "lib_warn() { :; }\n" + valid + loop
        ok = self.bash(script, API="api.ex.com", FRONTEND="rmm.ex.com", MESHDOMAIN="")
        self.assertEqual(ok.returncode, 0, ok.stdout)
        bad = self.bash(
            script, API="api.ex.com", FRONTEND="x; return 403", MESHDOMAIN="m"
        )
        self.assertEqual(bad.returncode, 1)
        self.assertIn("FRONTEND", bad.stdout)


if __name__ == "__main__":
    unittest.main()
