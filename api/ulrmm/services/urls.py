# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.urls import path

from . import views

urlpatterns = [
    path("<agent:agent_id>/", views.GetServices.as_view()),
    path("<agent:agent_id>/<str:svcname>/", views.GetEditActionService.as_view()),
]
