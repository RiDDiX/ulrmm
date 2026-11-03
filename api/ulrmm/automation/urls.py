# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.urls import path

from autotasks.views import GetAddAutoTasks
from checks.views import GetAddChecks

from . import views

policy_task = views.PolicyAutoTask.as_view()
patch_policy = views.UpdatePatchPolicy.as_view()

urlpatterns = [
    path("policies/", views.GetAddPolicies.as_view()),
    # the agent views also serve the checks and tasks of one policy
    path("policies/<int:policy>/checks/", GetAddChecks.as_view()),
    path("policies/<int:policy>/tasks/", GetAddAutoTasks.as_view()),
    path("policies/overview/", views.OverviewPolicy.as_view()),
    path("policies/<int:pk>/", views.GetUpdateDeletePolicy.as_view()),
    path("tasks/<int:task>/status/", policy_task),
    path("policies/<int:pk>/related/", views.GetRelated.as_view()),
    path("checks/<int:check>/status/", views.PolicyCheck.as_view()),
    path("tasks/<int:task>/run/", policy_task),
    path("patchpolicy/", patch_policy),
    path("patchpolicy/<int:pk>/", patch_policy),
    path("patchpolicy/reset/", views.ResetPatchPolicy.as_view()),
]
