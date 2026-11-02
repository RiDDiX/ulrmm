# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.urls import path

from . import views

urlpatterns = [
    path("policies/", views.Policies.as_view()),
    path("policies/<int:site_id>/", views.SitePolicy.as_view()),
    path("<str:agent_id>/", views.AgentLaps.as_view()),
    path("<str:agent_id>/rotate/", views.RotateNow.as_view()),
]
