# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.db import transaction
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import serializers
from rest_framework.decorators import api_view
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.response import Response

from accounts.utils import has_superuser_rights
from agents.models import Agent
from .models import BackupPolicy, Pairing, Profile
from .serializers import ProfileSerializer
from .service import agent_allowed, audit, capability, next_run


class PolicyInput(serializers.Serializer):
    name = serializers.CharField(max_length=100)
    config = ProfileSerializer()
    agents = serializers.ListField(
        child=serializers.CharField(max_length=200), max_length=500, allow_empty=False
    )


def editable(user, policy):
    if has_superuser_rights(user):
        return True
    assignments = list(policy.profile_set.select_related("agent"))
    if not assignments:
        return policy.owner_id == user.pk
    return all(agent_allowed(user, p.agent, "can_manage_images") for p in assignments)


def apply(profile, policy, config, user):
    old_mode = profile.network_mode
    for key, value in config.items():
        setattr(profile, key, value)
    profile.policy = policy
    profile.operator = user
    profile.next_run = next_run(profile, timezone.now())
    profile.save()
    if profile.network_mode != old_mode:
        Pairing.objects.filter(agent_id=profile.agent_id).delete()
    audit(profile.agent, user.username, f"Backup policy {policy.pk} applied.")


@api_view(["GET", "POST", "PUT", "DELETE"])
@transaction.atomic
def policies(request, pk=None):
    user = request.user
    if (
        not user.is_active
        or user.agent_id
        or user.is_installer_user
        or user.block_dashboard_login
        or not (
            has_superuser_rights(user) or (user.role and user.role.can_manage_images)
        )
    ):
        raise PermissionDenied()
    if request.method == "GET":
        return Response(
            [
                {
                    "id": p.pk,
                    "name": p.name,
                    "config": {"keep_last": 0, **p.config},
                    "agents": list(
                        p.profile_set.values_list("agent__agent_id", flat=True)
                    ),
                }
                for p in BackupPolicy.objects.order_by("name", "pk")
                if editable(user, p)
            ]
        )
    if request.method == "DELETE":
        if pk is None:
            return Response(status=405)
        policy = get_object_or_404(BackupPolicy.objects.select_for_update(), pk=pk)
        if not editable(user, policy):
            raise PermissionDenied()
        if policy.profile_set.exists():
            return Response(
                {"detail": "Remove all devices from this policy before deleting it."},
                status=409,
            )
        policy.delete()
        audit(None, user.username, f"Backup policy {pk} deleted.")
        return Response(status=204)
    data = PolicyInput(data=request.data)
    data.is_valid(raise_exception=True)
    data = data.validated_data
    ids = set(data["agents"])
    agents = list(
        Agent.objects.select_for_update().filter(agent_id__in=ids).order_by("pk")
    )
    if len(agents) != len(ids) or any(
        not agent_allowed(user, a, "can_manage_images") for a in agents
    ):
        raise PermissionDenied()
    if any(
        not capability(a).get("native") or not capability(a)["supported"]
        for a in agents
    ):
        raise ValidationError(
            "Review an available native backup source for every selected device."
        )
    if pk is not None:
        policy = get_object_or_404(BackupPolicy.objects.select_for_update(), pk=pk)
        if not editable(user, policy):
            raise PermissionDenied()
    else:
        policy = BackupPolicy(owner=user)
    policy.name = data["name"]
    config = data["config"]
    policy.config = {
        k: (v.isoformat(timespec="minutes") if k == "schedule_time" and v else v)
        for k, v in config.items()
    }
    policy.save()
    for agent in agents:
        profile, _ = Profile.objects.select_for_update().get_or_create(agent=agent)
        apply(profile, policy, config, user)
    # Changes to a shared policy also reach prior assignments outside the selection.
    for profile in (
        Profile.objects.select_for_update()
        .filter(policy=policy)
        .exclude(agent__in=agents)
        .select_related("agent")
    ):
        apply(profile, policy, config, user)
    return Response({"id": policy.pk}, status=200 if pk else 201)
