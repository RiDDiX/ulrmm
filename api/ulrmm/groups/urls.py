# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.urls import path

from . import views

urlpatterns = [
    path("", views.GetAddGroups.as_view()),
    path("<int:pk>/", views.GetEditDeleteGroup.as_view()),
    path("<int:pk>/agents/", views.GroupAgents.as_view()),
    path("preview/", views.PreviewGroup.as_view()),
    path("tags/", views.GetAddTags.as_view()),
    path("tags/<int:pk>/", views.EditDeleteTag.as_view()),
    path("agents/<agent_id>/tags/", views.AgentTags.as_view()),
]
