# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.urls import path

from . import policies, views
from .models import Transfer

urlpatterns = [
    path("policies/", policies.policies),
    path("policies/<int:pk>/", policies.policies),
    path("agents/<str:agent_id>/", views.device),
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
    for op in ("begin", "part", "seal")
]
