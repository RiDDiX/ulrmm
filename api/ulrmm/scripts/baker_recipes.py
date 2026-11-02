# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from model_bakery.recipe import Recipe

from ulrmm import sample_data
from ulrmm.constants import AgentPlat, ScriptShell, ScriptType


def _script(kind: str, shell: str, **fields) -> Recipe:
    """User-defined script named "Test <kind> Script" with a matching description."""
    label = f"Test {kind}".rstrip()
    return Recipe(
        "scripts.Script",
        name=f"{label} Script",
        description=f"{label} Desc",
        shell=shell,
        script_type=ScriptType.USER_DEFINED,
        **fields,
    )


script = _script("", ScriptShell.CMD)

batch_script = _script(
    "Batch",
    ScriptShell.CMD,
    script_body=sample_data.clear_print_spool_bat,
    args=["one", "two"],
)

ps_script = _script(
    "Powershell",
    ScriptShell.POWERSHELL,
    script_body=sample_data.check_storage_pool_health_ps1,
    args=["one"],
    supported_platforms=[AgentPlat.WINDOWS],
)

py_script = _script(
    "Python",
    ScriptShell.PYTHON,
    script_body=sample_data.show_temp_dir_py,
    supported_platforms=[AgentPlat.WINDOWS, AgentPlat.LINUX],
    category="py stuff",
)

bash_script = _script(
    "Bash",
    ScriptShell.SHELL,
    script_body=sample_data.redhat_insights,
    args=["one"],
    supported_platforms=[AgentPlat.LINUX],
    category="RHSA",
)
