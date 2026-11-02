# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.urls import path

from . import views

urlpatterns = [
    path("schedules/", views.GetAddSchedules.as_view()),
    path("schedules/<int:pk>/", views.GetUpdateDeleteSchedule.as_view()),
    path("schedules/preview/", views.PreviewSchedule.as_view()),
    path("schedules/agent/<agent:agent_id>/", views.AgentSchedules.as_view()),
]
