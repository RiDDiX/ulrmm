# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.urls import path

from . import views

urlpatterns = [
    path("", views.GetAddAutoTasks.as_view()),
    path("<int:pk>/", views.GetEditDeleteAutoTask.as_view()),
    path("<int:pk>/run/", views.RunAutoTask.as_view()),
]
