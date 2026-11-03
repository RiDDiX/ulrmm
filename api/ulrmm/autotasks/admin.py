# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.contrib import admin

from .models import AutomatedTask, TaskResult

for model in (AutomatedTask, TaskResult):
    admin.site.register(model)
