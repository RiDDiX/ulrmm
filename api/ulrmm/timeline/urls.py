# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.urls import path

from . import views

urlpatterns = [
    path("", views.FleetTimeline.as_view()),
    path("<str:agent_id>/", views.AgentTimeline.as_view()),
]
