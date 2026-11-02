# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.urls import path

from . import views

urlpatterns = [
    path("<agent:agent_id>/", views.GetWindowsUpdates.as_view()),
    path("<agent:agent_id>/scan/", views.ScanWindowsUpdates.as_view()),
    path("<agent:agent_id>/install/", views.InstallWindowsUpdates.as_view()),
    path("<int:pk>/", views.EditWindowsUpdates.as_view()),
]
