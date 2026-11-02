# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.urls import path

from . import views

urlpatterns = [
    path("settings/", views.Settings.as_view()),
    path("sync/", views.Sync.as_view()),
    path("clients/", views.Clients.as_view()),
    path("vlans/", views.Vlans.as_view()),
]
