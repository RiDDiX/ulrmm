# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from scripts.models import ENV_DENIED, check_env_vars


def test_env_denylist_takes_interpreter_hooks():
    for name in (
        "PERL5OPT",
        "perl5lib",
        "PERLLIB",
        "RUBYOPT",
        "RUBYLIB",
        "JAVA_TOOL_OPTIONS",
        "_JAVA_OPTIONS",
        "JDK_JAVA_OPTIONS",
        "OPENSSL_CONF",
        "OPENSSL_MODULES",
        "GCONV_PATH",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "GIT_SSH_COMMAND",
        "SSLKEYLOGFILE",
    ):
        assert ENV_DENIED.fullmatch(name), name
    for name in ("PERL5OPTS_X", "OPENSSL_CONFIG_DIR", "XDG_RUNTIME_DIR", "JAVA_HOME"):
        assert not ENV_DENIED.fullmatch(name), name
    check_env_vars(["JAVA_HOME=/opt/jdk"])
