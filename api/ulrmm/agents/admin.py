# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.contrib import admin

from .models import Agent, AgentCustomField, AgentHistory, Note


@admin.register(Agent)
class AgentAdmin(admin.ModelAdmin):
    # the uninstall code is a secret; agent-reported blobs are not edited here
    exclude = ("uninstall_code",)
    readonly_fields = ("wmi_detail", "services", "disks")


for model in (Note, AgentCustomField, AgentHistory):
    admin.site.register(model)
