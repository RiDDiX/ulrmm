# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.urls import path

from . import views

urlpatterns = [
    path("<agent:agent_id>/services/", views.PosixServices.as_view()),
    path("<agent:agent_id>/services/<str:name>/", views.PosixServiceAction.as_view()),
    path("<agent:agent_id>/logs/", views.PosixLogs.as_view()),
]
