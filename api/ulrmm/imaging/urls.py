# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.urls import path

from . import policies, views
from .models import Transfer

urlpatterns = [
    path("storage/", views.storage),
    path("policies/", policies.policies),
    path("policies/<int:pk>/", policies.policies),
    path("targets/", views.targets),
    path("targets/<int:pk>/", views.targets),
    path("fleet/", views.fleet),
    path("holds/<int:pk>/confirm/", views.hold_confirm),
    path("agents/<str:agent_id>/", views.device),
    path("agents/<str:agent_id>/effective/", views.device_effective),
    path("agents/<str:agent_id>/check/", views.device_check),
    path("agents/<str:agent_id>/hooks/confirm/", views.device_hooks_confirm),
    path("agents/<str:agent_id>/runs/", views.runs),
    path("agents/<str:agent_id>/runs/<uuid:run_id>/", views.runs),
    path("agents/<str:agent_id>/runs/<uuid:run_id>/cancel/", views.run_cancel),
    path("retention/preview/", views.retention_preview),
    path("policies/<int:pk>/hooks/confirm/", policies.hooks_confirm),
    path("agents/<str:agent_id>/capture/", views.capture),
    path("agents/<str:agent_id>/pair/", views.pair),
    path("transfers/<uuid:pair_id>/poll/", views.poll, name="imaging-poll"),
    path(
        "agents/<str:agent_id>/images/<uuid:image_id>/capture-access/",
        views.access,
        {"direction": Transfer.Direction.CAPTURE},
    ),
    path(
        "agents/<str:agent_id>/images/<uuid:image_id>/restore-access/",
        views.access,
        {"direction": Transfer.Direction.RESTORE},
    ),
    path("agents/<str:agent_id>/images/<uuid:image_id>/cancel/", views.cancel),
    path("agents/<str:agent_id>/images/<uuid:image_id>/recheck/", views.recheck),
    path("agents/<str:agent_id>/images/<uuid:image_id>/protect/", views.protect),
    path("agents/<str:agent_id>/images/<uuid:image_id>/", views.delete_image),
    path("transfers/<uuid:transfer_id>/", views.transfer, name="imaging-transfer"),
    path("transfers/<uuid:transfer_id>/data/", views.transfer, {"operation": "data"}),
    path(
        "transfers/<uuid:transfer_id>/manifest/",
        views.transfer,
        {"operation": "manifest"},
    ),
    path(
        "transfers/<uuid:transfer_id>/complete/",
        views.transfer,
        {"operation": "complete"},
    ),
    path(
        "transfers/<uuid:transfer_id>/integrity-failed/",
        views.transfer,
        {"operation": "integrity-failed"},
    ),
]

urlpatterns += [
    path("transfers/<uuid:transfer_id>/" + op + "/", views.transfer, {"operation": op})
    for op in ("begin", "part", "parts", "seal", "progress")
]
