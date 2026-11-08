# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""install_lib.sh nginx TLS and log settings, field keys, log modes, and the
age encryption of backup.sh/restore.sh."""

import base64
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from django.conf import settings

REPO = Path(settings.BASE_DIR).parents[1]
LIB = REPO / "riddix" / "scripts" / "install_lib.sh"
CIPHERS = (
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"
)

pytestmark = pytest.mark.skipif(not shutil.which("bash"), reason="needs bash")


def _bash(script, *args, env=None, rc=0):
    r = subprocess.run(
        ["bash", "-c", script, "bash", *args],
        capture_output=True,
        text=True,
        timeout=60,
        env={**os.environ, **(env or {})},
    )
    assert r.returncode == rc, r.stdout + r.stderr
    return r.stdout


def _lib(call, env=None, rc=0):
    return _bash(f'. "{LIB}"\n{call}', env=env, rc=rc)


def _function(path, name):
    return re.search(
        rf"^{name}\(\) \{{\n.*?^\}}\n", Path(path).read_text(), re.S | re.M
    ).group(0)


def _fake_nginx(tmp_path, line):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    nginx = bin_dir / "nginx"
    nginx.write_text(
        f"#!/bin/sh\necho 'nginx version: nginx/1.28.0' >&2\necho '{line}' >&2\n"
    )
    nginx.chmod(0o755)
    return {"PATH": f"{bin_dir}:{os.environ['PATH']}"}


def _sites(env=None):
    return {
        name: _lib(f"{name} {args} /c/cert.pem /c/key.pem", env=env)
        for name, args in (
            ("rmm_nginx_conf", "api.example.com rmm.example.com"),
            ("mesh_nginx_conf", "mesh.example.com"),
            ("frontend_nginx_conf", "rmm.example.com api.example.com mesh.example.com"),
        )
    }


@pytest.mark.parametrize(
    "line, curve",
    [
        ("built with OpenSSL 3.0.15 3 Sep 2024", "X25519:prime256v1:secp384r1"),
        (
            "built with OpenSSL 3.5.1 1 Jul 2025",
            "X25519MLKEM768:X25519:prime256v1:secp384r1",
        ),
        (
            "built with OpenSSL 3.0.13 30 Jan 2024 (running with OpenSSL 3.5.4 30 Sep 2025)",
            "X25519MLKEM768:X25519:prime256v1:secp384r1",
        ),
        (
            "built with OpenSSL 4.0.0 1 Apr 2026",
            "X25519MLKEM768:X25519:prime256v1:secp384r1",
        ),
        ("built with LibreSSL 3.9.0", "X25519:prime256v1:secp384r1"),
    ],
)
def test_ecdh_curve_follows_openssl(tmp_path, line, curve):
    assert _lib("nginx_ecdh_curve", env=_fake_nginx(tmp_path, line)) == curve + "\n"


def test_every_vhost_and_nginx_conf_get_the_tls_settings(tmp_path):
    env = _fake_nginx(tmp_path, "built with OpenSSL 3.5.1 1 Jul 2025")
    texts = {**_sites(env), "nginx_conf_text": _lib("nginx_conf_text", env=env)}
    for name, text in texts.items():
        indent = "        " if name == "nginx_conf_text" else "    "
        for line in (
            "ssl_protocols TLSv1.2 TLSv1.3;",
            f"ssl_ciphers {CIPHERS};",
            "ssl_prefer_server_ciphers on;",
            "ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;",
            "ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1:secp384r1;",
        ):
            assert text.count(f"\n{indent}{line}\n") == 1, (name, line)
        assert "secp384r1;\n" in text and "EDH+AESGCM" not in text, name


def test_access_logs_leave_url_secrets_out():
    sites = _sites()
    api, mesh, web = (
        sites["rmm_nginx_conf"],
        sites["mesh_nginx_conf"],
        sites["frontend_nginx_conf"],
    )
    assert "access.log ulrmm_api if=$ignore_ua;" in api
    assert " combined" not in api
    assert "log_format ulrmm_api " in api and "$request " not in api
    assert "/var/log/nginx/frontend-access.log ulrmm_web;" in web
    assert "log_format ulrmm_web " in web
    https = mesh.split("listen 443 ssl;", 1)[1]
    assert "    access_log off;\n" in https
    # what the map does with real request URIs
    rules = re.findall(r'^    "(~\*?)\^?(.*?)" "(.*?)";$', api, re.M)
    assert len(rules) == 5

    def logged(uri, rule_set=rules[:4]):
        for flag, pattern, value in rule_set:
            m = re.match(
                "^" + pattern.replace("(?<", "(?P<").replace("\\?", r"\?"),
                uri,
                re.I if flag == "~*" else 0,
            )
            if m:
                return re.sub(r"\$(\w+)", lambda g: m.group(g.group(1)), value)
        return uri

    assert logged("/clients/0f1e2d3c-uid/deploy/?fmt=sh") == "/clients/-/deploy/?fmt=sh"
    assert logged("/packages/download/tok123/") == "/packages/download/-/"
    assert logged("/deploy/iso/download/tok456/") == "/deploy/iso/download/-/"
    assert (
        logged("/oidc/x/login/callback/?code=abc&state=xyz")
        == "/oidc/x/login/callback/?-"
    )
    assert logged("/ws/dashinfo/?access_token=k") == "/ws/dashinfo/?-"
    assert logged("/agents/?country_code=de") == "/agents/?country_code=de"
    assert logged("/clients/") == "/clients/"


def test_ensure_field_keys_once(tmp_path):
    ls = tmp_path / "local_settings.py"
    ls.write_text('SECRET_KEY = "x"\n')
    env = {"local_settings": str(ls)}
    _lib("ensure_field_keys", env=env)
    keys = re.findall(r'^FIELD_ENCRYPTION_KEYS = \["(.*)"\]$', ls.read_text(), re.M)
    assert len(keys) == 1 and len(base64.b64decode(keys[0], validate=True)) == 32
    assert oct(ls.stat().st_mode & 0o777) == "0o600"
    _lib("ensure_field_keys", env=env)
    assert (
        re.findall(r'^FIELD_ENCRYPTION_KEYS = \["(.*)"\]$', ls.read_text(), re.M)
        == keys
    )


@pytest.mark.parametrize(
    "script, first, then",
    [
        ("install.sh", "ensure_enroll_key\nensure_field_keys\n", "build_agents_step"),
        (
            "update.sh",
            "  ensure_enroll_key\n  ensure_field_keys\n",
            "build_agents_step",
        ),
        ("restore.sh", "ensure_enroll_key\nensure_field_keys\n", "build_agents_step"),
        ("install.sh", "ensure_age ||", "nginx_conf_text |"),
        ("restore.sh", "ensure_age ||", 'unpack_backup "$backup_file"'),
    ],
)
def test_scripts_call_the_new_steps(script, first, then):
    text = (REPO / script).read_text()
    assert text.count(first) == 1, first
    assert text.index(first) < text.index(then)
    # the nginx.conf text lives in install_lib.sh only
    assert "nginx_conf_text() {" not in text


def test_harden_logs_restricts_celery(tmp_path):
    log = tmp_path / "log"
    stubs = f'sudo() {{ printf "%s\\n" "$*" >>{log}; [ "$1" != tee ] || cat >/dev/null; }}\n'
    _lib(stubs + "harden_logs", env={"USER": "rmmuser"})
    calls = log.read_text().splitlines()
    for line in (
        "chown rmmuser:rmmuser /var/log/celery",
        "chmod 750 /var/log/celery",
        "find /var/log/celery -maxdepth 1 -type f -exec chmod 640 {} +",
    ):
        assert line in calls, line
    text = _lib("logrotate_text", env={"USER": "rmmuser"})
    assert (
        "/var/log/celery/*.log /rmm/api/ulrmm/ulrmm/private/log/*_debug.log "
        "/var/log/ulrmm-backup.log {" in text
        and "copytruncate" in text
    )


# backup.sh / restore.sh with a stand-in for age: what reaches it, and what
# comes back; the real round trip is in the round's report.
AGE_STUB = """
age() {
  local out='' id='' mode=''
  printf 'age %s\\n' "$*" >>"$AGE_LOG"
  while [ $# -gt 0 ]; do
    case "$1" in
    -e) mode=e ;;
    -d) mode=d ;;
    -o) out=$2; shift ;;
    -i) id=$2; shift ;;
    -r | -R) shift ;;
    *) in=$1 ;;
    esac
    shift
  done
  if [ "$mode" = e ]; then
    { printf 'age-encryption.org/v1\\n'; base64; } >"$out"
  else
    [ "$(cat "$id")" = right ] || return 1
    tail -n +2 "$in" | base64 -d
  fi
}
fail() { echo "FAIL: $*"; exit 1; }
lib_die() { echo "DIE: $*"; exit 1; }
set -o pipefail
"""


def _age(tmp_path, body, env=None, rc=0):
    funcs = _function(REPO / "backup.sh", "age_recipients") + _function(
        REPO / "backup.sh", "write_archive"
    )
    funcs += _function(REPO / "restore.sh", "unpack_backup")
    staging = tmp_path / "staging"
    (staging / "rmm").mkdir(parents=True, exist_ok=True)
    (staging / "rmm" / "local_settings.py").write_text('SECRET_KEY = "s3cr3t"\n')
    (tmp_path / "right").write_text("right")
    (tmp_path / "wrong").write_text("wrong")
    return _bash(
        AGE_STUB + funcs + "age_args=()\n" + body,
        env={"AGE_LOG": str(tmp_path / "age.log"), "T": str(tmp_path), **(env or {})},
        rc=rc,
    )


def test_backup_encrypts_to_the_recipients(tmp_path):
    key = "age1" + "q" * 58
    _age(
        tmp_path,
        'age_recipients\nwrite_archive "$T/staging" "$T/b.tar.age"\n',
        env={"AGE_RECIPIENTS": f"{key} {key[:-1]}x"},
    )
    assert (tmp_path / "age.log").read_text() == (
        f"age -e -r {key} -r {key[:-1]}x -o {tmp_path}/b.tar.age\n"
    )
    data = (tmp_path / "b.tar.age").read_bytes()
    assert data.startswith(b"age-encryption.org/v1\n") and b"s3cr3t" not in data

    out = _age(
        tmp_path,
        'age_identity="$T/right"\nmkdir "$T/out"\nunpack_backup "$T/b.tar.age" "$T/out"\n'
        'cat "$T/out/rmm/local_settings.py"\n',
    )
    assert out == 'SECRET_KEY = "s3cr3t"\n'
    for identity, message in (
        ("", "is encrypted, pass its age key file"),
        ("$T/wrong", "could not be decrypted"),
    ):
        out = _age(
            tmp_path,
            f'age_identity="{identity}"\nmkdir -p "$T/o2"\nunpack_backup "$T/b.tar.age" "$T/o2"\n',
            rc=1,
        )
        assert message in out, identity


def test_backup_recipients_file_and_bad_values(tmp_path):
    (tmp_path / "recipients").write_text("age1" + "p" * 58 + "\n")
    _age(
        tmp_path,
        'age_recipients\nwrite_archive "$T/staging" "$T/b.tar.age"\n',
        env={"AGE_RECIPIENTS": str(tmp_path / "recipients")},
    )
    assert f"age -e -R {tmp_path}/recipients -o" in (tmp_path / "age.log").read_text()
    for value, message in (
        ("ssh-ed25519 AAAA", "'ssh-ed25519' is not an age1"),
        (str(tmp_path / "missing"), "cannot read the age recipients file"),
    ):
        out = _age(tmp_path, "age_recipients\n", env={"AGE_RECIPIENTS": value}, rc=1)
        assert message in out, value


def test_backup_failure_records_an_event_on_auto_runs(tmp_path):
    py = tmp_path / "py"
    py.write_text('#!/bin/sh\nprintf "%s|" "$@" >>"$(dirname "$0")/py.log"\n')
    py.chmod(0o755)
    fail = _function(REPO / "backup.sh", "fail")
    script = f'say() {{ :; }}\nPY={py}\nMANAGE=m.py\n{fail}mode=$1\nfail "disk full."\n'
    _bash(script, "manual", rc=1)
    assert not (tmp_path / "py.log").exists()
    _bash(script, "auto", rc=1)
    assert (tmp_path / "py.log").read_text() == (
        "m.py|security_event|backup_failed|high|--detail|disk full.|"
    )
    text = (REPO / "backup.sh").read_text()
    assert 'mktemp -d -p "$out_dir" .staging-XXXXXXXX' in text
    assert "${CRON_CMD} >> ${CRON_LOG} 2>&1" in text


def test_backup_without_recipients_stays_a_plain_tar(tmp_path):
    out = _age(
        tmp_path,
        'age_recipients\nwrite_archive "$T/staging" "$T/b.tar"\n'
        'mkdir "$T/out"\nunpack_backup "$T/b.tar" "$T/out"\ncat "$T/out/rmm/local_settings.py"\n',
        env={"AGE_RECIPIENTS": ""},
    )
    assert out == 'SECRET_KEY = "s3cr3t"\n'
    assert not (tmp_path / "age.log").exists()
    text = (REPO / "backup.sh").read_text()
    assert "security_event backup_unencrypted warning" in text
    assert "[ ${#age_args[@]} -eq 0 ] || target+=.age\n" in text
