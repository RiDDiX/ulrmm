# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.urls import path

from . import views

per_agent = {"resetall": views.ResetAllChecksStatus.as_view(), "run": views.run_checks}

urlpatterns = [
    path("", views.GetAddChecks.as_view()),
    path("<int:pk>/", views.GetUpdateDeleteCheck.as_view()),
    path("<int:pk>/reset/", views.ResetCheck.as_view()),
    *(path(f"<agent:agent_id>/{name}/", view) for name, view in per_agent.items()),
    path("<int:pk>/history/", views.GetCheckHistory.as_view()),
    path("<str:target>/<int:pk>/csbulkrun/", views.bulk_run_checks),
]
