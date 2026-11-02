# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""install_lib.sh, backup.sh, restore.sh and the agent build: the parts the
enrollment key, the agent CA and large software packages added."""

import base64
import grp
import os
import re
import shutil
import subprocess
import tarfile
from datetime import timedelta
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

import pytest
from django.conf import settings
from django.test.utils import override_settings

from deploy import signing
from ulrmm.helpers import agent_ver
from ulrmm.utils import AGENT_ID_RE

REPO = Path(settings.BASE_DIR).parents[1]
LIB = REPO / "riddix" / "scripts" / "install_lib.sh"

pytestmark = pytest.mark.skipif(not shutil.which("bash"), reason="needs bash")


def _bash(script: str, *args: str, env=None, rc=0) -> str:
    r = subprocess.run(
        ["bash", "-c", script, "bash", *args],
        capture_output=True,
        text=True,
        timeout=60,
        env={**os.environ, **(env or {})},
    )
    assert r.returncode == rc, r.stderr
    return r.stdout


def _lib(call: str, *args: str, env=None, rc=0) -> str:
    return _bash(f'. "{LIB}"\n{call}', *args, env=env, rc=rc)


def _function(path: Path, name: str) -> str:
    return re.search(
        rf"^{name}\(\) \{{\n.*?^\}}\n", path.read_text(), re.S | re.M
    ).group(0)


def _block(conf: str, head: str) -> str:
    """Body of the first block that starts with head (4-space indented)."""
    return re.search(
        rf"^    {re.escape(head)} \{{\n(.*?)^    \}}\n", conf, re.S | re.M
    ).group(1)


def _sites():
    return {
        name: _lib(f"{name} {args} /c/cert.pem /c/key.pem")
        for name, args in (
            ("rmm_nginx_conf", "api.example.com rmm.example.com"),
            ("mesh_nginx_conf", "mesh.example.com"),
            ("frontend_nginx_conf", "rmm.example.com api.example.com mesh.example.com"),
        )
    }


def test_rmm_site_asks_for_agent_certificates():
    conf = _sites()["rmm_nginx_conf"]
    https = conf.split("listen 443 ssl reuseport;", 1)[1]
    head = https.split("location ", 1)[0]
    for line in (
        "ssl_certificate /c/cert.pem;",
        "ssl_client_certificate /etc/ulrmm/agent-ca/ca.pem;",
        "ssl_verify_client optional_no_ca;",
        "ssl_verify_depth 1;",
    ):
        assert f"    {line}\n" in head, line
    # only the 443 server of the API name
    assert "ssl_" not in conf.split("listen 443 ssl reuseport;", 1)[0]

    params = (
        "        uwsgi_param SSL_CLIENT_VERIFY $ssl_client_verify;\n"
        "        uwsgi_param SSL_CLIENT_FINGERPRINT $ssl_client_fingerprint;\n"
    )
    api = _block(conf, "location /")
    assert api.startswith(
        "        uwsgi_pass  ulrmm;\n        include     /etc/nginx/uwsgi_params;\n"
        + params
    ), api

    assert "        auth_request /api/v3/natsauth/;\n" in _block(
        conf, "location ~ ^/natsws"
    )
    auth = _block(conf, "location = /api/v3/natsauth/")
    assert auth == (
        "        internal;\n        uwsgi_pass  ulrmm;\n"
        "        include     /etc/nginx/uwsgi_params;\n"
        + params
        + "        uwsgi_param ULRMM_NATS_URI $request_uri;\n"
        + "        uwsgi_pass_request_body off;\n"
        '        uwsgi_param CONTENT_LENGTH "";\n'
    ), auth
    # the other locations stay without the variables
    for head in ("location /static/", "location ~ ^/ws/", "location /agentdist/"):
        assert "SSL_CLIENT" not in _block(conf, head), head


def test_natsws_bound_path_reaches_nats_server_as_natsws():
    nats = _block(_sites()["rmm_nginx_conf"], "location ~ ^/natsws")
    lines = [line.strip() for line in nats.splitlines()]
    auth = lines.index("auth_request /api/v3/natsauth/;")
    rewrite = next(i for i, line in enumerate(lines) if line.startswith("rewrite "))
    proxy = lines.index("proxy_pass http://127.0.0.1:9235;")
    assert auth < rewrite < proxy
    _, pattern, target, flag = lines[rewrite].rstrip(";").split()
    assert (target, flag) == ("/natsws", "break")
    agent_id = "aB3_-" * 8
    assert AGENT_ID_RE.fullmatch(agent_id)
    assert re.search(pattern, f"/natsws/{agent_id}")
    for uri in ("/natsws", "/natsws/", "/natsws/a/b", "/natsws/a.b", "/natswsx"):
        assert not re.search(pattern, uri), uri


def test_ensure_token_pepper_once(tmp_path):
    ls = tmp_path / "local_settings.py"
    ls.write_text('SECRET_KEY = "x"\n')
    env = {"local_settings": str(ls)}
    _lib("ensure_token_pepper", env=env)
    peppers = re.findall(r'^AGENT_TOKEN_PEPPERS = \["(.*)"\]$', ls.read_text(), re.M)
    assert len(peppers) == 1
    assert len(base64.b64decode(peppers[0], validate=True)) == 32
    assert oct(ls.stat().st_mode & 0o777) == "0o600"
    loaded = {}
    exec(ls.read_text(), loaded)
    assert loaded["AGENT_TOKEN_PEPPERS"] == peppers

    # a restored local_settings.py keeps its pepper
    _lib("ensure_token_pepper", env=env)
    assert (
        re.findall(r'^AGENT_TOKEN_PEPPERS = \["(.*)"\]$', ls.read_text(), re.M)
        == peppers
    )
    assert ls.read_text().startswith('SECRET_KEY = "x"\n')


def test_sec2_settings_defaults():
    assert settings.AGENT_TOKEN_PEPPERS == [] or all(
        len(base64.b64decode(k, validate=True)) == 32
        for k in settings.AGENT_TOKEN_PEPPERS
    )
    assert settings.AGENT_ACCESS_TTL == timedelta(days=7)
    assert settings.AGENT_REFRESH_TTL == timedelta(days=60)
    assert settings.OFFLINE_GRACE == timedelta(days=30)
    assert settings.E2E_REKEY_SECONDS == 3600
    assert settings.E2E_REKEY_BYTES == 64 << 20
    assert settings.E2E_REKEY_MESSAGES == 100_000
    assert settings.E2E_CLOCK_WINDOW == 30
    assert agent_ver(settings.SEC_R2_MIN_AGENT) > agent_ver(settings.SEC_R1_MIN_AGENT)


def test_mesh_and_frontend_sites_ask_for_no_certificate():
    sites = _sites()
    for name in ("mesh_nginx_conf", "frontend_nginx_conf"):
        assert "ssl_verify_client" not in sites[name], name
        assert "ssl_client_certificate" not in sites[name], name


def test_refresh_site_reads_the_server_certificate_not_the_ca(tmp_path):
    # refresh_site passes the old ssl_certificate/_key on; the CA line must not match
    site = tmp_path / "rmm.conf"
    site.write_text(_sites()["rmm_nginx_conf"])
    awk = _function(LIB, "refresh_site").split("\n")[3:5]
    out = _bash(
        "\n".join(line.replace("sudo awk", "awk") for line in awk)
        + '\nprintf "%s %s" "$cert" "$key"',
        env={"f": str(site)},
    )
    assert out == "/c/cert.pem /c/key.pem"


def test_ensure_enroll_key_once(tmp_path):
    ls = tmp_path / "local_settings.py"
    ls.write_text('SECRET_KEY = "x"\n')
    env = {"local_settings": str(ls)}
    _lib("ensure_enroll_key", env=env)
    first = re.findall(r'^ENROLL_SIGNING_KEY = "(.*)"$', ls.read_text(), re.M)
    assert len(first) == 1
    assert len(base64.b64decode(first[0], validate=True)) == 32
    assert oct(ls.stat().st_mode & 0o777) == "0o600"
    with override_settings(ENROLL_SIGNING_KEY=first[0]):
        assert signing.key_id()

    _lib("ensure_enroll_key", env=env)
    assert re.findall(r'^ENROLL_SIGNING_KEY = "(.*)"$', ls.read_text(), re.M) == first
    assert ls.read_text().startswith('SECRET_KEY = "x"\n')


def test_ensure_agent_ca(tmp_path):
    log = tmp_path / "log"
    stubs = (
        f'sudo() {{ printf "sudo %s\\n" "$*" >>{log}; }}\n'
        f'manage() {{ printf "manage %s\\n" "$*" >>{log}; }}\n'
    )
    group = grp.getgrgid(os.getgid()).gr_name
    _lib(stubs + "ensure_agent_ca --reset-certs-if-new", env={"USER": "rmmuser"})
    assert log.read_text().splitlines() == [
        f"sudo install -d -m 0755 -o rmmuser -g {group} /etc/ulrmm/agent-ca",
        "manage ensure_agent_ca --reset-certs-if-new",
    ]
    log.unlink()
    # no directory, no command
    _lib(
        stubs + "sudo() { return 1; }\nensure_agent_ca",
        env={"USER": "rmmuser"},
        rc=1,
    )
    assert not log.exists()


def _packages(tmp_path, limit=1000):
    pkgs = tmp_path / "packages"
    (pkgs / ".uploads").mkdir(parents=True)
    small, edge, big = "a" * 64, "b" * 64, "c" * 64
    (pkgs / small).write_bytes(b"x" * 10)
    (pkgs / edge).write_bytes(b"x" * limit)
    (pkgs / big).write_bytes(b"x" * (limit + 1))
    (pkgs / ".incoming-abc").write_bytes(b"partial")
    (pkgs / ".uploads" / "7.part").write_bytes(b"partial")
    return pkgs, small, edge, big


def _backup_run(pkgs, out, with_large="false"):
    backup = REPO / "backup.sh"
    script = (
        "".join(
            _function(backup, n) for n in ("pkg_files", "pack_packages", "large_lines")
        )
        # stands in for the database: sha256 and name of the large packages
        + f'psql() {{ printf "%s Big Suite 2026\\n" "{"c" * 64}"; }}\n'
        + 'large=()\npack_packages "$1" >/dev/null || exit 9\nlarge_lines\n'
    )
    return _bash(
        script,
        str(out),
        env={
            "PACKAGES_DIR": str(pkgs),
            "LARGE_PACKAGE": "1000",
            "with_large": with_large,
        },
    )


def _members(tar_path):
    with tarfile.open(tar_path) as tar:
        return sorted(tar.getnames())


def test_backup_leaves_large_packages_out(tmp_path):
    pkgs, small, edge, big = _packages(tmp_path)
    out = tmp_path / "packages.tar"
    lines = _backup_run(pkgs, out)
    assert _members(out) == sorted([f"./{small}", f"./{edge}"])
    assert lines == f"LARGE_PACKAGE={big} 1001 Big Suite 2026\n"

    lines = _backup_run(pkgs, out, with_large="true")
    assert _members(out) == sorted([f"./{small}", f"./{edge}", f"./{big}"])
    assert lines == ""


def test_backup_with_no_package_files(tmp_path):
    pkgs = tmp_path / "packages"
    (pkgs / ".uploads").mkdir(parents=True)
    out = tmp_path / "packages.tar"
    assert _backup_run(pkgs, out) == ""
    assert _members(out) == []


def test_backup_takes_the_agent_ca():
    text = (REPO / "backup.sh").read_text()
    assert "AGENT_CA_DIR=/etc/ulrmm/agent-ca\n" in text
    assert (
        'for f in "${AGENT_CA_DIR}/ca.key" "${AGENT_CA_DIR}/ca.pem"; do\n'
        '  if sudo test -f "$f"; then\n'
        '    sudo cp -p "$f" "${STAGING}/agent-ca/"'
    ) in text
    assert '  large_lines\n} >"${STAGING}/MANIFEST"' in text


def test_restore_lists_missing_large_packages(tmp_path):
    pkgs, small, edge, big = _packages(tmp_path)
    manifest = tmp_path / "MANIFEST"
    other = "d" * 64
    manifest.write_text(
        "FORMAT=1\n"
        f"LARGE_PACKAGE={big} 1001 Big Suite 2026\n"
        f"LARGE_PACKAGE={other} 5000000000 Capture One 16\n"
        "LARGE_PACKAGE=../../etc/passwd 1 nope\n"
    )
    (pkgs / big).unlink()
    (pkgs / other).write_bytes(b"put back by hand")
    out = _bash(
        _function(REPO / "restore.sh", "missing_packages") + 'missing_packages "$@"',
        str(manifest),
        str(pkgs),
    )
    assert out == f"Big Suite 2026 (1001 bytes, sha256 {big})\n"
    assert (
        _bash(
            _function(REPO / "restore.sh", "missing_packages")
            + 'missing_packages "$@"',
            str(tmp_path / "none"),
            str(pkgs),
        )
        == ""
    )


@pytest.mark.parametrize(
    "script, first, then",
    [
        # nginx reads ca.pem, the agent build bakes the public key
        ("install.sh", "ensure_enroll_key\n", "build_agents_step"),
        ("install.sh", "ensure_agent_ca ||", 'rmm_nginx_conf "$backenddomain"'),
        ("update.sh", "  ensure_enroll_key\n", "build_agents_step"),
        (
            "update.sh",
            "  ensure_agent_ca --reset-certs-if-new ||",
            "refresh_site rmm rmm_nginx_conf",
        ),
        ("restore.sh", "ensure_enroll_key\n", "build_agents_step"),
        (
            "restore.sh",
            "ensure_agent_ca --reset-certs-if-new ||",
            'rmm_nginx_conf "$API"',
        ),
        # the CA comes out of the staging dir before lib_cleanup removes it
        (
            "restore.sh",
            '"${B}/agent-ca/${name}" "${AGENT_CA_DIR}/${name}"',
            "lib_cleanup\n",
        ),
        ("restore.sh", "mapfile -t missing_pkgs", "lib_cleanup\n"),
        # the token migration digests with the pepper
        ("install.sh", "ensure_field_keys\nensure_token_pepper\n", "manage migrate"),
        ("update.sh", "  ensure_field_keys\n  ensure_token_pepper\n", "manage migrate"),
        ("restore.sh", "ensure_field_keys\nensure_token_pepper\n", "manage migrate"),
        # the release window rows exist only after migrate
        ("restore.sh", "manage migrate ||", "manage open_release_window --all-active"),
        # the backup's pepper is in place before a new one could be made
        (
            "restore.sh",
            'install -m 600 "$backup_settings" "$local_settings"',
            "ensure_token_pepper\n",
        ),
    ],
)
def test_scripts_call_the_steps_in_order(script, first, then):
    text = (REPO / script).read_text()
    assert text.count(first) == 1, first
    assert text.index(first) < text.index(then), (first, then)
    # manage() exists before ensure_agent_ca runs
    if "ensure_agent_ca" in first:
        assert text.index("manage() {") < text.index(first)


@pytest.mark.parametrize(
    "script",
    [
        "install.sh",
        "update.sh",
        "restore.sh",
        "backup.sh",
        "riddix/scripts/install_lib.sh",
        "riddix/agents/build_agents.sh",
    ],
)
def test_scripts_parse(script):
    _bash(f'bash -n "{REPO / script}"')


def _write_brand():
    spec = spec_from_file_location(
        "write_brand", REPO / "riddix" / "agents" / "write_brand.py"
    )
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_write_brand_bakes_the_enroll_key(tmp_path, capsys):
    wb = _write_brand()
    wb.demo()
    assert wb.enroll_pubkey() == signing.public_key_b64()
    with override_settings(ENROLL_SIGNING_KEY=""):
        assert wb.enroll_pubkey() == ""
    with override_settings(ENROLL_SIGNING_KEY="bm90LTMyLWJ5dGVz"):
        assert wb.enroll_pubkey() == ""
    assert "ENROLL_SIGNING_KEY must hold 32 bytes" in capsys.readouterr().out

    (tmp_path / "agent").mkdir()
    (tmp_path / "build").mkdir()
    key = signing.public_key_b64()
    ident = {k: "x" for k in re.findall(r"\{(Ident\w+)\}", wb.BRAND_GO)}
    ident["IdentWinSvcName"] = ident["IdentArtifact"] = "ulrmm-agent"
    wb.write(
        str(tmp_path),
        "UniversalLocal RMM",
        "",
        "",
        b"",
        ident,
        "{{61D095D9-C6CE-4D60-B192-4C6699822C40}",
        enroll_key=key,
    )
    brand = (tmp_path / "agent" / "brand.go").read_text()
    assert f'\tBrandEnrollPubKey = "{key}"\n' in brand

    # build_agents.sh reads the baked value back for enroll-pubkey.txt
    build = (REPO / "riddix" / "agents" / "build_agents.sh").read_text()
    line = re.search(r"^ENROLL_PUBKEY=.*$", build, re.M).group(0)
    assert (
        _bash(line + '\nprintf %s "$ENROLL_PUBKEY"', env={"SRC": str(tmp_path)}) == key
    )
    assert (
        'printf \'%s\\n\' "$ENROLL_PUBKEY" >"$TMP/enroll-pubkey.txt"\n'
        'install -m 0644 "$TMP/enroll-pubkey.txt" "$DIST/.enroll-pubkey.txt.$$.new"\n'
        'mv -f "$DIST/.enroll-pubkey.txt.$$.new" "$DIST/enroll-pubkey.txt"\n'
    ) in build
    assert build.index('mv -f "$stage" "$DIST/$b"') < build.index("enroll-pubkey.txt")
