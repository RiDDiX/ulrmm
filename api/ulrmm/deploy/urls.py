# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.urls import path

from . import iso_views, mtls_views, policy_views, views

urlpatterns = [
    path("matrix/", views.BuilderMatrix.as_view()),
    path("render/", views.BuilderRender.as_view()),
    path("download/", views.BuilderDownload.as_view()),
    path("iso/library/", iso_views.IsoLibrary.as_view()),
    path("iso/library/scan/", iso_views.IsoScan.as_view()),
    path("iso/library/progress/", iso_views.IsoProgress.as_view()),
    path("iso/library/<int:pk>/cancel/", iso_views.IsoCancel.as_view()),
    path("iso/library/<int:pk>/retry/", iso_views.IsoRetry.as_view()),
    path("iso/library/<int:pk>/verify/", iso_views.IsoVerify.as_view()),
    path("iso/library/<int:pk>/", iso_views.IsoDelete.as_view()),
    path("iso/library/<int:pk>/link/", iso_views.IsoLink.as_view()),
    path("iso/download/<str:token>/", iso_views.IsoDownload.as_view()),
    path("iso/uploads/", iso_views.IsoUploads.as_view()),
    path("iso/uploads/<str:uid>/", iso_views.IsoUploadDetail.as_view()),
    path("iso/uploads/<str:uid>/finish/", iso_views.IsoFinishUpload.as_view()),
    path("iso/plan/", iso_views.IsoPlan.as_view()),
    path("iso/seed/", iso_views.IsoSeed.as_view()),
    path("iso/build/", iso_views.IsoBuild.as_view()),
    path("iso/jobs/<str:job_id>/", iso_views.IsoJob.as_view()),
    path("security/", mtls_views.AgentSecurity.as_view()),
    path("security/events/", mtls_views.SecurityEvents.as_view()),
    path("security/policies/", policy_views.RotationPolicies.as_view()),
    path("security/matrix/", policy_views.TrustMatrix.as_view()),
    path("agents/<str:agent_id>/cert/", mtls_views.AgentCert.as_view()),
    path("agents/<str:agent_id>/cert/reset/", mtls_views.ResetAgentCert.as_view()),
    path("agents/<str:agent_id>/identity/", mtls_views.AgentIdentityInfo.as_view()),
    path("agents/<str:agent_id>/quarantine/", mtls_views.QuarantineAgent.as_view()),
    path("agents/<str:agent_id>/release/", mtls_views.ReleaseAgent.as_view()),
    path(
        "agents/<str:agent_id>/reset-identity/",
        mtls_views.ResetAgentIdentity.as_view(),
    ),
    path("agents/<str:agent_id>/block/", mtls_views.BlockAgent.as_view()),
    path("security/rotate/", mtls_views.SecurityRotate.as_view()),
    path("security/command-key/rotate/", mtls_views.RotateCommandKey.as_view()),
    path("security/pins/promote/", mtls_views.PromotePins.as_view()),
]
