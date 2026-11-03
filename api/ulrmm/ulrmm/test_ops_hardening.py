# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""redis requirepass, the nftables firewall (firewall.sh), rotate-secrets.sh and
the frontend CSP switch. The real nft run is in the round's report."""

import json
import os
import re
import shutil
import stat

import pytest

from ulrmm.test_ops_transport import LIB, REPO, _bash, _lib

FW = REPO / "riddix" / "scripts" / "firewall.sh"
ROTATE = REPO / "riddix" / "scripts" / "rotate-secrets.sh"

# every external command the scripts run with a secret nearby: each call is
# logged with its argv before the real one runs
WRAPPED = (
    "awk sed tee grep tail mktemp mv python3.12 openssl cat tr od dirname "
    "install mkdir chmod touch rm cut"
).split()

STUBS = {
    # sudo logs itself, drops its options and runs the rest
    "sudo": 'while [ "${1#-}" != "$1" ]; do case "$1" in -iu | -u) shift ;; esac; shift; done\n'
    'exec "$@"\n',
    "systemctl": "",
    "redis-cli": '[ "$REDISCLI_AUTH" = "$(awk \'$1 == "requirepass" {p = $2} END {print p}\' "$REDIS_CONF")" ] '
    "&& echo PONG\n",
    "psql": 'cat >>"$T/sql"\n',
    "node": 'case "$*" in *--logintokengen*) echo "$NEW_KEY" ;; *) echo "$OLD_KEY" ;; esac\n',
}


@pytest.fixture
def sandbox(tmp_path):
    """stub dir first in PATH, the argv log in $T/argv"""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    real_path = os.environ["PATH"]
    for name in WRAPPED:
        if shutil.which(name):
            (bin_dir / name).write_text(
                f'#!/bin/sh\nprintf "%s\\n" "{name} $*" >>"$T/argv"\n'
                f'PATH="{real_path}" exec {name} "$@"\n'
            )
    for name, body in STUBS.items():
        (bin_dir / name).write_text(
            f'#!/bin/bash\nprintf "%s\\n" "{name} $*" >>"$T/argv"\n{body}'
        )
    for f in bin_dir.iterdir():
        f.chmod(0o755)
    (tmp_path / "redis.conf").write_text(
        "bind 127.0.0.1 -::1\n# requirepass foobared\nrequirepass old\n"
    )
    ls = tmp_path / "local_settings.py"
    ls.write_text('SECRET_KEY = "s"\n')
    ls.chmod(0o600)
    return {
        "PATH": f"{bin_dir}:{real_path}",
        "T": str(tmp_path),
        "REDIS_CONF": str(tmp_path / "redis.conf"),
        "local_settings": str(ls),
    }


def _argv(env):
    path = os.path.join(env["T"], "argv")
    return open(path).read() if os.path.exists(path) else ""


def _calls(env, line):
    return _argv(env).splitlines().count(line)


def _ls(env, key):
    m = re.findall(rf'^{key} = "(.*)"$', open(env["local_settings"]).read(), re.M)
    return m[-1] if m else None


def _requirepass(env):
    return re.findall(r"^requirepass (.*)$", open(env["REDIS_CONF"]).read(), re.M)


NO_SLEEP = "sleep() { :; }\n"


def test_ensure_redis_password_once_and_off_argv(sandbox):
    _lib(NO_SLEEP + "ensure_redis_password", env=sandbox)
    pw = _ls(sandbox, "REDIS_PASSWORD")
    assert re.fullmatch(r"[0-9a-f]{64}", pw)
    assert _requirepass(sandbox) == [pw]
    conf = open(sandbox["REDIS_CONF"]).read()
    assert "# requirepass foobared\n" in conf and "bind 127.0.0.1 -::1\n" in conf
    argv = _argv(sandbox)
    assert _calls(sandbox, "systemctl restart redis-server") == 1
    assert pw not in argv
    assert oct(os.stat(sandbox["local_settings"]).st_mode & 0o777) == "0o600"

    # a second run keeps the password and does not restart redis
    _lib(NO_SLEEP + "ensure_redis_password", env=sandbox)
    assert _ls(sandbox, "REDIS_PASSWORD") == pw and _requirepass(sandbox) == [pw]
    assert _calls(sandbox, "systemctl restart redis-server") == 1


def test_redis_password_of_a_restored_backup_is_kept(sandbox):
    with open(sandbox["local_settings"], "a") as f:
        f.write('REDIS_PASSWORD = "' + "ab" * 32 + '"\n')
    _lib(NO_SLEEP + "ensure_redis_password", env=sandbox)
    assert _requirepass(sandbox) == ["ab" * 32]


def test_redis_that_does_not_come_back_fails(sandbox):
    open(os.path.join(sandbox["T"], "bin", "redis-cli"), "w").write("#!/bin/sh\n")
    out = _bash(
        f'. "{LIB}"\n{NO_SLEEP}ensure_redis_password 2>&1; echo "rc=$?"', env=sandbox
    )
    assert "does not answer redis-cli ping with REDIS_PASSWORD" in out
    assert out.endswith("rc=1\n")


@pytest.mark.parametrize(
    "reply, rc", [("PONG", 0), ("NOAUTH Authentication required.", 0), ("", 1)]
)
def test_start_redis_accepts_an_earlier_requirepass(sandbox, reply, rc):
    open(os.path.join(sandbox["T"], "bin", "redis-cli"), "w").write(
        f"#!/bin/sh\necho '{reply}'\n"
    )
    _lib(NO_SLEEP + "start_redis", env=sandbox, rc=rc)


def _index(text, needle):
    assert text.count(needle) == 1, needle
    return text.index(needle)


def test_redis_password_comes_before_every_redis_user():
    update = (REPO / "update.sh").read_text()
    main = update[update.index("main() {") :]
    stop = _index(main, "for s in celerybeat celery nginx nats-api nats rmm daphne; do")
    ensure = _index(main, "ensure_redis_password ||")
    assert stop < ensure < main.index("manage pre_update_tasks")
    assert (
        ensure
        < main.index("celery -A ulrmm purge")
        < main.index("\n  start_services\n")
    )
    for script, settings_written, first_user in (
        ("install.sh", 'install -m 600 /dev/null "$local_settings"', "manage migrate"),
        (
            "restore.sh",
            'install -m 600 "$backup_settings" "$local_settings"',
            "manage migrate",
        ),
    ):
        text = (REPO / script).read_text()
        ensure = _index(text, "ensure_redis_password ||")
        assert text.index(settings_written) < ensure < text.index(first_user), script
    restore = (REPO / "restore.sh").read_text()
    assert restore.index("ensure_redis_password") < restore.index(
        "Starting the services"
    )


def test_update_runs_the_firewall_after_the_services_unless_told_not_to():
    text = (REPO / "update.sh").read_text()
    main = text[text.index("main() {") :]
    step = _index(main, "    firewall_step\n")
    assert (
        main.index("\n  start_services\n")
        < main.index("sudo systemctl reload nginx")
        < step
    )
    assert 'if [ "$no_firewall" != true ]; then\n    firewall_step' in main
    assert '--no-firewall) no_firewall=true forward+=("$1") ;;' in main
    assert "  --no-firewall  " in text[: text.index("EOF\n}")]
    assert re.search(r'^SCRIPT_VERSION="(\d+)"', text, re.M).group(1) != "180"
    for script in ("install.sh", "restore.sh"):
        text = (REPO / script).read_text()
        assert "\nfirewall_step\ncase $? in\n0) firewall_state=" in text, script
        assert "\n2) firewall_state='off (FIREWALL=off" in text, script


def _fw(body, env=None, rc=0):
    return _bash(f'. "{FW}"\n{body}', env=env, rc=rc)


@pytest.fixture
def fw_env(tmp_path):
    ls = tmp_path / "local_settings.py"
    ls.write_text("")
    return {
        "FW_CONF": str(tmp_path / "firewall.conf"),
        "FW_RULES": str(tmp_path / "etc" / "firewall.nft"),
        "FW_UNIT": str(tmp_path / "ulrmm-firewall.service"),
        "FW_RUN": str(tmp_path / "run"),
        "local_settings": str(ls),
        "T": str(tmp_path),
    }


NO_HOST = "sshd() { return 1; }\nss() { :; }\nsystemctl() { :; }\n"


def _nft_calls(fw_env):
    calls = open(os.path.join(fw_env["T"], "calls")).read().splitlines()
    return [c for c in calls if c.startswith("nft ")]


def _ports(text):
    return (
        re.findall(r"^\t\ttcp dport (\S+) accept$", text, re.M),
        re.findall(r"^\t\tudp dport (\S+) accept$", text, re.M),
    )


def test_render_default(fw_env):
    text = _fw(NO_HOST + "read_conf\nrender", env=fw_env)
    assert text.startswith(
        "table inet ulrmm\ndelete table inet ulrmm\ntable inet ulrmm {\n\tchain input {\n"
        "\t\ttype filter hook input priority filter; policy drop;\n"
        '\t\tiif "lo" accept\n\t\tct state established,related accept\n'
    )
    assert _ports(text) == (["22", "80", "443", "21115-21117"], ["21116"])
    for line in (
        "\t\tudp sport 67 udp dport 68 accept\n",
        "\t\tip6 saddr fe80::/10 udp sport 547 udp dport 546 accept\n",
        "nd-neighbor-solicit, nd-neighbor-advert",
    ):
        assert line in text
    # nothing but the one input chain of the own table
    assert (
        "flush" not in text and "hook output" not in text and "hook forward" not in text
    )
    assert re.findall(r"^\S.*$", text, re.M) == [
        "table inet ulrmm",
        "delete table inet ulrmm",
        "table inet ulrmm {",
        "}",
    ]


def test_render_follows_sshd_nats_and_the_conf(fw_env):
    host = (
        "sshd() { printf 'port 2222\\nport 22\\n'; }\n"
        "systemctl() { echo 'Listen=[::]:2022 (Stream)'; }\n"
        "ss() { echo 'LISTEN 0 128 0.0.0.0:2200 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))'; "
        "echo 'LISTEN 0 128 0.0.0.0:5432 0.0.0.0:* users:((\"postgres\",pid=2,fd=3))'; }\n"
    )
    open(fw_env["local_settings"], "w").write(
        "USE_NATS_STANDARD = True\nNATS_STANDARD_PORT = 4333\n"
    )
    open(fw_env["FW_CONF"], "w").write(
        '# own ports\nTCP_PORTS="8443 9100-9101 443"\nUDP_PORTS=51820 # wireguard\n'
    )
    tcp, udp = _ports(_fw(host + "read_conf\nrender", env=fw_env))
    assert tcp == ["22", "2022", "2200", "2222", "80", "443", "21115-21117", "4333"] + [
        "8443",
        "9100-9101",
    ]
    assert udp == ["21116", "51820"]

    open(fw_env["local_settings"], "w").write("USE_NATS_STANDARD = True\n")
    assert "4222" in _ports(_fw(NO_HOST + "read_conf\nrender", env=fw_env))[0]
    open(fw_env["local_settings"], "w").write("USE_NATS_STANDARD = False\n")
    assert "4222" not in _ports(_fw(NO_HOST + "read_conf\nrender", env=fw_env))[0]


@pytest.mark.parametrize("value", ["22;", "80,443", "$(id)", "1-2-3"])
def test_conf_refuses_anything_but_ports(fw_env, value):
    open(fw_env["FW_CONF"], "w").write(f"TCP_PORTS={value}\n")
    out = _bash(f'. "{FW}"\n{NO_HOST}read_conf 2>&1', env=fw_env, rc=1)
    assert "is not a port or a port range" in out


FW_TOOLS = """
nft() { printf 'nft %s\\n' "$*" >>"$T/calls"; [ "$*" != "list table inet ulrmm" ] || [ ! -e "$T/gone" ]; }
systemd-run() { printf 'systemd-run %s\\n' "$*" >>"$T/calls"; }
systemctl() { printf 'systemctl %s\\n' "$*" >>"$T/calls"; }
command() { [ "$2" != nft ] && [ "$2" != systemd-run ] && builtin command "$@" || echo /usr/sbin/nft; }
"""


def test_apply_checks_arms_the_rollback_then_loads(fw_env):
    out = _fw(NO_HOST + FW_TOOLS + "apply", env=fw_env)
    token = re.search(r"^confirm token: ([0-9a-f]{16})$", out, re.M).group(1)
    calls = open(os.path.join(fw_env["T"], "calls")).read().splitlines()
    rules = f"{fw_env['FW_RUN']}/rules.nft"
    check = calls.index(f"nft -c -f {rules}")
    arm = calls.index(
        "systemd-run --quiet --unit=ulrmm-firewall-rollback --on-active=300 "
        "--timer-property=AccuracySec=1s /usr/sbin/nft delete table inet ulrmm"
    )
    assert check < arm < calls.index(f"nft -f {rules}")
    assert stat.S_IMODE(os.stat(fw_env["FW_RUN"]).st_mode) == 0o700
    assert open(rules).read().startswith("table inet ulrmm\n")
    assert not os.path.exists(fw_env["FW_RULES"])

    _fw(NO_HOST + FW_TOOLS + "confirm 0000000000000000 2>&1", env=fw_env, rc=1)
    assert not os.path.exists(fw_env["FW_RULES"])
    out = _fw(NO_HOST + FW_TOOLS + f"confirm {token}", env=fw_env)
    assert "ulrmm-firewall.service loads it at boot" in out
    assert stat.S_IMODE(os.stat(fw_env["FW_RULES"]).st_mode) == 0o600
    unit = open(fw_env["FW_UNIT"]).read()
    assert re.search(
        rf"^ExecStart=\S+bash {re.escape(os.path.realpath(FW))} boot$", unit, re.M
    )
    assert "WantedBy=sysinit.target" in unit and "Before=network-pre.target" in unit
    calls = open(os.path.join(fw_env["T"], "calls")).read()
    assert "systemctl stop ulrmm-firewall-rollback.timer" in calls
    assert "systemctl enable ulrmm-firewall.service" in calls
    # the token is used up
    _fw(NO_HOST + FW_TOOLS + f"confirm {token} 2>&1", env=fw_env, rc=1)


def test_confirm_after_the_rollback_fails(fw_env):
    token = re.search(
        r"^confirm token: (\S+)$", _fw(NO_HOST + FW_TOOLS + "apply", env=fw_env), re.M
    ).group(1)
    open(os.path.join(fw_env["T"], "gone"), "w").close()
    out = _fw(NO_HOST + FW_TOOLS + f"confirm {token} 2>&1", env=fw_env, rc=1)
    assert "the rollback already deleted the table" in out
    assert not os.path.exists(fw_env["FW_RULES"])


def test_firewall_off_in_the_conf_loads_nothing(fw_env):
    open(fw_env["FW_CONF"], "w").write("FIREWALL=Off\n")
    open(os.path.join(fw_env["T"], "gone"), "w").close()
    out = _fw(NO_HOST + FW_TOOLS + "apply", env=fw_env)
    assert "nothing loaded" in out and "confirm token" not in out
    calls = _nft_calls(fw_env)
    assert calls == ["nft list table inet ulrmm"]


def test_firewall_off_in_the_conf_removes_a_loaded_table(fw_env):
    open(fw_env["FW_CONF"], "w").write("FIREWALL=off\n")
    for key in ("FW_UNIT", "FW_RULES"):
        os.makedirs(os.path.dirname(fw_env[key]), exist_ok=True)
        open(fw_env[key], "w").write("x\n")
    out = _fw(NO_HOST + FW_TOOLS + "apply", env=fw_env)
    assert "the loaded table and its boot unit were removed" in out
    calls = open(os.path.join(fw_env["T"], "calls")).read()
    assert "nft delete table inet ulrmm" in calls
    assert "systemctl disable ulrmm-firewall.service" in calls
    assert not os.path.exists(fw_env["FW_UNIT"])
    assert not os.path.exists(fw_env["FW_RULES"])


def test_boot_renders_the_ssh_ports_of_now(fw_env):
    host = "sshd() { printf 'port 2222\\n'; }\nss() { :; }\nsystemctl() { :; }\n"
    _fw(host + FW_TOOLS + "boot", env=fw_env)
    calls = _nft_calls(fw_env)
    boot = f"{fw_env['FW_RUN']}/boot.nft"
    assert calls == [f"nft -c -f {boot}", f"nft -f {boot}"]
    assert "2222" in _ports(open(boot).read())[0]


def test_boot_keeps_the_ssh_ports_of_the_saved_rules(fw_env):
    os.makedirs(os.path.dirname(fw_env["FW_RULES"]), exist_ok=True)
    open(fw_env["FW_RULES"], "w").write(
        "\t\ttcp dport 2222 accept\n\t\ttcp dport 80 accept\n"
    )
    _fw(NO_HOST + FW_TOOLS + "boot", env=fw_env)
    tcp = _ports(open(f"{fw_env['FW_RUN']}/boot.nft").read())[0]
    assert "2222" in tcp and tcp.count("80") == 1


def test_boot_falls_back_to_the_saved_rules(fw_env):
    tools = FW_TOOLS.replace(
        "nft() { printf", 'nft() { [ "$1" != -c ] || return 1; printf'
    )
    _fw(NO_HOST + tools + "boot", env=fw_env)
    calls = _nft_calls(fw_env)
    assert calls == [f"nft -f {fw_env['FW_RULES']}"]


def test_boot_with_firewall_off_loads_nothing(fw_env):
    open(fw_env["FW_CONF"], "w").write("FIREWALL=off\n")
    _fw(NO_HOST + FW_TOOLS + "boot", env=fw_env)
    assert not os.path.exists(os.path.join(fw_env["T"], "calls"))


@pytest.mark.parametrize(
    "apply_out, check_rc, expected",
    [
        ("confirm token: abc", 0, ["apply", "check", "confirm abc"]),
        ("confirm token: abc", 1, ["apply", "check", "revert"]),
        ("firewall: FIREWALL=off in x, nothing loaded", 0, ["apply"]),
    ],
)
def test_firewall_step_keeps_the_table_only_after_the_check(
    tmp_path, apply_out, check_rc, expected
):
    log = tmp_path / "log"
    stub = (
        f'sudo() {{ local a="$*"; echo "${{a#bash /rmm/riddix/scripts/firewall.sh }}" >>{log}; '
        f'case "$3" in apply) echo "{apply_out}" ;; check) return {check_rc} ;; esac; }}\n'
    )
    out = _lib(stub + "firewall_step >/dev/null 2>&1; echo rc=$?")
    assert log.read_text().splitlines() == expected
    rc = {"confirm abc": "0", "revert": "1"}.get(expected[-1], "2")
    assert f"rc={rc}" in out


def test_frontend_csp_header_is_one_switch():
    text = LIB.read_text()
    assert text.count("\nFRONTEND_CSP_HEADER='Content-Security-Policy'\n") == 1
    web = _lib(
        "frontend_nginx_conf rmm.example.com api.example.com mesh.example.com c k"
    )
    assert web.count("add_header Content-Security-Policy \"default-src 'self';") == 2
    assert "Report-Only" not in web
    # report frames come from the API, the SSO form posts there and is redirected on
    assert (
        web.count(
            "frame-src 'self' https://mesh.example.com https://api.example.com blob:;"
        )
        == 2
    )
    assert web.count("form-action 'self' https://api.example.com https:\" always;") == 2
    report = _lib(
        "FRONTEND_CSP_HEADER=Content-Security-Policy-Report-Only\n"
        "frontend_nginx_conf rmm.example.com api.example.com mesh.example.com c k"
    )
    assert (
        report.count(
            "add_header Content-Security-Policy-Report-Only \"default-src 'self';"
        )
        == 2
    )


# rotate-secrets.sh: sourced, manage() and the paths replaced


def _rotate(env, body, rc=0):
    stub = (
        'manage() { printf "manage %s key=%s\\n" "$1" "${ULRMM_NEW_MESH_KEY:+set}" >>"$T/argv"; '
        'case "$1" in check_mesh) echo "Mesh device id ok: x" ;; esac; }\n'
    )
    return _bash(f'. "{ROTATE}"\n{stub}{NO_SLEEP}{body}', env=env, rc=rc)


def test_rotate_redis(sandbox):
    out = _rotate(sandbox, "rotate_redis")
    pw = _ls(sandbox, "REDIS_PASSWORD")
    assert re.fullmatch(r"[0-9a-f]{64}", pw) and _requirepass(sandbox) == [pw]
    argv = _argv(sandbox)
    assert pw not in argv and pw not in out
    assert argv.index("systemctl restart redis-server") < argv.index(
        "systemctl restart rmm daphne celery celerybeat"
    )


LOCAL_DB = """SECRET_KEY = "s"  # schlüssel
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'ulrmm',
        'USER': 'abcdefgh',
        'PASSWORD': 'oldAppPw1',
        'HOST': 'localhost',
        'PORT': '5432',
    }
}

MESH_USERNAME = "x"
"""


@pytest.fixture
def db_env(sandbox, tmp_path):
    if not shutil.which("python3.12"):
        pytest.skip("needs python3.12")
    open(sandbox["local_settings"], "w").write(LOCAL_DB)
    data = tmp_path / "meshcentral" / "meshcentral-data"
    data.mkdir(parents=True)
    (data / "config.json").write_text(
        json.dumps(
            {"settings": {"postgres": {"user": "meshusr", "password": "oldMeshPw1"}}}
        )
    )
    return {**sandbox, "MESH_DIR": str(tmp_path / "meshcentral")}


def test_rotate_db(db_env):
    out = _rotate(db_env, "rotate_db")
    ls_text = open(db_env["local_settings"]).read()
    app_pw = re.search(r"'PASSWORD': '([0-9a-f]{48})',", ls_text).group(1)
    assert ls_text == LOCAL_DB.replace("oldAppPw1", app_pw)
    assert stat.S_IMODE(os.stat(db_env["local_settings"]).st_mode) == 0o600
    cfg_path = os.path.join(db_env["MESH_DIR"], "meshcentral-data", "config.json")
    mesh_pw = json.load(open(cfg_path))["settings"]["postgres"]["password"]
    assert re.fullmatch(r"[0-9a-f]{48}", mesh_pw)
    assert stat.S_IMODE(os.stat(cfg_path).st_mode) == 0o600
    sql = open(os.path.join(db_env["T"], "sql")).read()
    assert sql == (
        f"ALTER ROLE \"abcdefgh\" WITH PASSWORD '{app_pw}';\n"
        f"ALTER ROLE \"meshusr\" WITH PASSWORD '{mesh_pw}';\n"
    )
    argv = _argv(db_env)
    for pw in (app_pw, mesh_pw):
        assert pw not in argv and pw not in out
    assert "role abcdefgh" in out and "role meshusr" in out
    order = [
        "systemctl stop celerybeat celery rmm daphne nats-api",
        "sudo -iu postgres psql -q -v ON_ERROR_STOP=1",
        "manage create_natsapi_conf",
        "systemctl start celerybeat celery rmm daphne nats-api",
        "systemctl stop meshcentral",
        "systemctl start meshcentral",
    ]
    assert [argv.index(c) for c in order] == sorted(argv.index(c) for c in order)
    assert not [f for f in os.listdir(os.path.dirname(cfg_path)) if f.startswith(".")]


def test_rotate_db_failed_alter_changes_nothing(db_env):
    open(os.path.join(db_env["T"], "bin", "psql"), "w").write("#!/bin/sh\nexit 3\n")
    out = _rotate(db_env, "rotate_db 2>&1", rc=1)
    assert "ALTER ROLE abcdefgh failed, nothing changed" in out
    assert open(db_env["local_settings"]).read() == LOCAL_DB
    # the stopped services come back
    assert "systemctl start celerybeat celery rmm daphne nats-api" in _argv(db_env)


def test_rotate_mesh(db_env):
    keys = {"OLD_KEY": "a" * 160, "NEW_KEY": "b" * 160}
    out = _rotate({**db_env, **keys}, "trap start_stopped EXIT\nrotate_mesh")
    assert _ls(db_env, "MESH_TOKEN_KEY") == "b" * 160
    argv = _argv(db_env)
    assert "manage shell key=set" in argv and "b" * 160 not in argv + out
    assert argv.index("systemctl stop meshcentral") < argv.index(
        "node node_modules/meshcentral --logintokenkey --logintokengen"
    )
    assert argv.index("systemctl start meshcentral") < argv.index(
        "systemctl restart rmm daphne celery celerybeat"
    )
    assert "check_mesh works with the new key" in out

    same = {**db_env, "OLD_KEY": "c" * 160, "NEW_KEY": "c" * 160}
    out = _rotate(same, "trap start_stopped EXIT\nrotate_mesh 2>&1", rc=1)
    assert "MeshCentral made no new login token key" in out
    assert _ls(db_env, "MESH_TOKEN_KEY") == "b" * 160
    assert _calls(db_env, "systemctl start meshcentral") == 2
