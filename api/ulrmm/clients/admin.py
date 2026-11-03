# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.contrib import admin

from .models import ClientCustomField, Client, Deployment, Site, SiteCustomField

for model in (Client, Site, Deployment, ClientCustomField, SiteCustomField):
    admin.site.register(model)
