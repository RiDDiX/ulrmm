# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.urls import path

from . import views

urlpatterns = [
    path("fleet/", views.fleet),
    path("<agent:agent_id>/", views.agent_metrics),
    path("<agent:agent_id>/state/", views.agent_state),
    path("<agent:agent_id>/series/", views.agent_series),
]
