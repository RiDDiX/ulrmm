# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.contrib import admin

from .models import (
    HostFacts,
    Patch,
    PatchDevice,
    PatchEvent,
    PatchHostState,
    PatchPolicy,
)


@admin.register(PatchEvent)
class PatchEventAdmin(admin.ModelAdmin):
    """Append-only: an edit or a delete here breaks the hash chain."""

    readonly_fields = [i.name for i in PatchEvent._meta.fields]

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


admin.site.register(Patch)
admin.site.register(PatchDevice)
admin.site.register(PatchPolicy)
admin.site.register(HostFacts)
admin.site.register(PatchHostState)
