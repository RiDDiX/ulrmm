# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.urls import path

from . import views

urlpatterns = [
    path("summary/", views.EncryptionSummary.as_view()),
    path("keys/<int:pk>/reveal/", views.RevealRecoveryKey.as_view()),
    path("<agent:agent_id>/", views.AgentEncryption.as_view()),
    path("<agent:agent_id>/collect/", views.CollectEncryption.as_view()),
    path("<agent:agent_id>/rotate/", views.RotateFileVaultKey.as_view()),
]
