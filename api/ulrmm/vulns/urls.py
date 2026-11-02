# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.urls import path

from . import views

urlpatterns = [
    path("", views.findings),
    path("summary/", views.summary),
    path("scan/", views.scan_fleet),
    path("findings/<int:pk>/ignore/", views.toggle_ignore),
    path("<agent_id>/", views.agent_findings),
    path("<agent_id>/scan/", views.scan_agent),
]
