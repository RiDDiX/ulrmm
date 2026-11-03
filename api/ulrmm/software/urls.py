# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.urls import path

from . import baseline_views, views

urlpatterns = [
    path("chocos/", views.chocos),
    path("baselines/", baseline_views.GetAddBaselines.as_view()),
    path("baselines/<int:pk>/", baseline_views.BaselineDetail.as_view()),
    path("baselines/<int:pk>/status/", baseline_views.BaselineStatusView.as_view()),
    path(
        "deployments/<int:pk>/baselines/",
        baseline_views.DeploymentBaselines.as_view(),
    ),
    path("catalog/", views.software_catalog),
    path("sdio/approvals/", views.SdioApprovals.as_view()),
    path("sdio/approvals/<int:pk>/", views.SdioApprovalDetail.as_view()),
    path("sdio/refresh/", views.RefreshSdio.as_view()),
    path("sdio/progress/", views.sdio_progress),
    path("sdio/offers/", views.sdio_offers),
    # the fleet-wide list is read only
    path("", views.GetSoftware.as_view(http_method_names=["get", "head", "options"])),
    path("<agent:agent_id>/", views.GetSoftware.as_view()),
    path("<agent:agent_id>/uninstall/", views.UninstallSoftware.as_view()),
    path("<agent:agent_id>/baseline/", baseline_views.AgentBaseline.as_view()),
    path(
        "<agent:agent_id>/baseline/retry/",
        baseline_views.RetryAgentBaseline.as_view(),
    ),
    path("<agent:agent_id>/drivers/", views.Drivers.as_view()),
    path("<agent:agent_id>/drivers/refresh/", views.RefreshDrivers.as_view()),
    path("<agent:agent_id>/drivers/catalog/check/", views.CheckDriverCatalog.as_view()),
    path(
        "<agent:agent_id>/drivers/catalog/install/",
        views.InstallCatalogDriver.as_view(),
    ),
    path(
        "<agent:agent_id>/drivers/catalog/jobs/<str:job>/",
        views.CatalogJob.as_view(),
    ),
]
