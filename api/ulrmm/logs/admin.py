# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.contrib import admin

from .models import AuditLog, DebugLog, PendingAction


class ReadOnlyLogAdmin(admin.ModelAdmin):
    # log rows are evidence: view only, even for staff
    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


admin.site.register(PendingAction)
admin.site.register(AuditLog, ReadOnlyLogAdmin)
admin.site.register(DebugLog, ReadOnlyLogAdmin)
