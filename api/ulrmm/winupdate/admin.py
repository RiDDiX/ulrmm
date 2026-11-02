# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.contrib import admin

from .models import WinUpdate, WinUpdatePolicy


@admin.register(WinUpdate)
class WinUpdateAdmin(admin.ModelAdmin):
    # __str__ shows the hostname, one join instead of a query per row
    list_select_related = ("agent",)


admin.site.register(WinUpdatePolicy)
