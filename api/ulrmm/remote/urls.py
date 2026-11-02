# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.urls import path

from . import views

# included from the root urlconf, so these stay under /core/ and /agents/
urlpatterns = [
    path("core/rustdesk/", views.RustDeskSettingsView.as_view()),
    path("core/rustdesk/releases/", views.RustDeskReleases.as_view()),
    path("core/rustdesk/releases/check/", views.CheckRustDeskReleases.as_view()),
    path("core/rustdesk/server/update/", views.UpdateRustDeskServer.as_view()),
    path("core/rustdesk/client/pin/", views.PinRustDeskClient.as_view()),
    path("core/rustdesk/clients/update/", views.UpdateRustDeskClients.as_view()),
    path("agents/<agent:agent_id>/rustdesk/", views.AgentRustDesk.as_view()),
    path("agents/<agent:agent_id>/rustdesk/deploy/", views.DeployRustDesk.as_view()),
    path("agents/<agent:agent_id>/rustdesk/update/", views.UpdateRustDesk.as_view()),
    path(
        "agents/<agent:agent_id>/rustdesk/password/",
        views.RevealRustDeskPassword.as_view(),
    ),
]
