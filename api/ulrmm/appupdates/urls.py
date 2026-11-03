# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.urls import path

from . import views

urlpatterns = [
    path("settings/", views.settings_view),
    path("sites/<int:pk>/policy/", views.site_policy),
    path("<agent_id>/", views.agent_updates),
    path("<agent_id>/collect/", views.collect),
    path("<agent_id>/apply/", views.apply),
    path("<agent_id>/exclude/", views.exclude),
    path("<agent_id>/policy/", views.agent_policy),
]
