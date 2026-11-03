# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.contrib import admin

from .models import CoreSettings, CustomField, Schedule

admin.site.register(CoreSettings)
admin.site.register(CustomField)
admin.site.register(Schedule)
