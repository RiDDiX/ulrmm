# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.contrib import admin

from .models import Check, CheckHistory, CheckResult

for model in (Check, CheckHistory, CheckResult):
    admin.site.register(model)
