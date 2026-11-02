# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.contrib import admin

from .models import ChocoSoftware, InstalledSoftware


@admin.register(ChocoSoftware)
class ChocoAdmin(admin.ModelAdmin):
    readonly_fields = ("added",)


admin.site.register(InstalledSoftware)
