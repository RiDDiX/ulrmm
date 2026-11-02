# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from model_bakery.recipe import Recipe

from ulrmm.constants import CheckType

check = Recipe("checks.Check")

# C: warns below 30 percent free, fails below 10
diskspace_check = check.extend(
    check_type=CheckType.DISK_SPACE, disk="C:", warning_threshold=30, error_threshold=10
)

ping_check = check.extend(check_type=CheckType.PING, ip="10.10.10.10")

# the check and its script share one name, as the dashboard shows it
script_check = check.extend(
    check_type=CheckType.SCRIPT, name="Script Name", script__name="Script Name"
)
