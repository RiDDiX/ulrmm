# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from contextlib import contextmanager
from typing import Optional

from django.db import transaction
from django.db.models import Q
from django.http import Http404
from django.shortcuts import get_object_or_404
from rest_framework import permissions
from rest_framework.exceptions import PermissionDenied

from agents.models import Agent
from ulrmm.constants import AGENT_DEFER


def _role(user):
    return user.get_and_set_role_cache()


def _is_super(user, role) -> bool:
    return bool(user.is_superuser or (role and role.is_superuser))


def _restrictions(role):
    clients = role.can_view_clients.all()
    sites = role.can_view_sites.all()
    return clients, sites, bool(clients) or bool(sites)


def _has_perm(request, perm: str) -> bool:
    user = request.user
    role = getattr(user, "role", None)
    if user.is_superuser or (role and role.is_superuser):
        return True
    if not role:
        return False
    # unknown perm names are a programmer error (AttributeError -> 500)
    return getattr(role, perm)


def _has_perm_on_agent(user, agent_id: str) -> bool:
    if getattr(user, "is_installer_user", False):
        return False

    role = _role(user)
    if _is_super(user, role):
        return True
    if not role:
        return False

    agents = Agent.objects.defer(*AGENT_DEFER).select_related("site__client")
    agent = get_object_or_404(agents, agent_id=agent_id)
    clients, sites, restricted = _restrictions(role)
    return not restricted or agent.site.client in clients or agent.site in sites


class RoleFlagPermission(permissions.BasePermission):
    """Lets the request through when the caller's role has `flag` set."""

    flag = ""

    def has_permission(self, r, view) -> bool:
        return _has_perm(r, self.flag)


def _is_restricted(user) -> bool:
    """A role limited to some clients or sites."""
    role = _role(user)
    return bool(role) and not _is_super(user, role) and _restrictions(role)[2]


def _has_perm_on_agent_or_hidden(user, agent_id: str) -> bool:
    """Like _has_perm_on_agent, but a restricted role gets False for a missing
    agent too, so it cannot tell missing ids from foreign ones."""
    try:
        return _has_perm_on_agent(user, agent_id)
    except Http404:
        if _is_restricted(user):
            return False
        raise


def _has_perm_on_client(user, client_id: int, *, manage: bool = False) -> bool:
    from clients.models import Client

    role = _role(user)
    if _is_super(user, role):
        return True
    if not role:
        return False

    client = get_object_or_404(Client, pk=client_id)

    clients, sites, restricted = _restrictions(role)
    if not restricted:
        return True
    if client in clients:
        return True
    # a site-scoped role may see the owning client, but not manage it
    if not manage and any(site.client_id == client.pk for site in sites):
        return True
    return False


def _has_perm_on_site(user, site_id: int) -> bool:
    from clients.models import Site

    role = _role(user)
    if _is_super(user, role):
        return True
    if not role:
        return False

    site = get_object_or_404(Site.objects.select_related("client"), pk=site_id)

    clients, sites, restricted = _restrictions(role)
    if not restricted:
        return True
    if site in sites:
        return True
    if site.client in clients:
        return True
    return False


def _scope_q(clients, sites) -> Q:
    return Q(site__client__in=clients) | Q(site__in=sites)


def _policy_ids_in_scope(clients, sites) -> list[int]:
    from automation.models import Policy

    scope = _scope_q(clients, sites)
    # one related_agents() per policy: cheap for the tens of policies a server
    # carries, the unfiltered list endpoints are its only callers
    return [
        policy.pk
        for policy in Policy.objects.all()
        if policy.related_agents().filter(scope).exists()
    ]


def _assigned_in_scope(policy, clients, sites) -> bool:
    """Every client, site and agent the policy is assigned to is the role's,
    whether or not that reaches an agent. A server default slot is nobody's."""
    from clients.models import Client, Site
    from core.models import CoreSettings

    named = Q(workstation_policy=policy) | Q(server_policy=policy)
    return not (
        CoreSettings.objects.filter(named).exists()
        or Client.objects.filter(named).exclude(pk__in=clients).exists()
        or Site.objects.filter(named)
        .exclude(Q(pk__in=sites) | Q(client__in=clients))
        .exists()
        or Agent.objects.filter(policy=policy)
        .exclude(_scope_q(clients, sites))
        .exists()
    )


def _may_assign_policy(user, policy) -> bool:
    """A scoped role hands its clients, sites and agents only policies it can
    see: one that reaches an agent in its scope, or one that reaches none and
    is assigned nowhere outside its scope."""
    role = _role(user)
    if _is_super(user, role) or not role:
        return True
    clients, sites, restricted = _restrictions(role)
    if not restricted:
        return True
    related = policy.related_agents()
    if related.filter(_scope_q(clients, sites)).exists():
        return True
    return not related.exists() and _assigned_in_scope(policy, clients, sites)


def _has_perm_on_policy(user, policy, *, manage: bool = False) -> bool:
    """A scoped role reaches a policy through the agents it applies to: seeing
    it needs one of them in scope, changing or running it needs all of them,
    since the change lands on every agent."""
    if getattr(user, "is_installer_user", False):
        return False

    role = _role(user)
    if _is_super(user, role):
        return True
    if not role:
        return False

    clients, sites, restricted = _restrictions(role)
    if not restricted:
        return True
    if policy is None:
        return False

    related = policy.related_agents()
    scope = _scope_q(clients, sites)
    if not related.filter(scope).exists():
        return False
    return not manage or not related.exclude(scope).exists()


def _may_manage_policy_pk(user, value) -> bool:
    """Scope of a policy pk from a request body, checked before validation
    so a scoped role learns nothing from the errors; resolved the way the
    serializer's related field does, a value naming no policy is left to it."""
    from automation.models import Policy

    if value in (None, "") or isinstance(value, bool):
        return True
    try:
        policy = Policy.objects.filter(pk=value).first()
    except (TypeError, ValueError):
        return True
    return policy is None or _has_perm_on_policy(user, policy, manage=True)


def _has_perm_on_item(user, item, *, manage: bool = False) -> bool:
    """Scope of a check or task: its agent, or the agents of its policy."""
    if item.agent_id:
        return _has_perm_on_agent(user, item.agent.agent_id)
    return _has_perm_on_policy(user, item.policy, manage=manage)


def _has_install_perm(request, site_id: Optional[int] = None) -> bool:
    from knox.models import AuthToken

    from clients.models import Deployment

    user = request.user
    if getattr(user, "is_installer_user", False):
        token = request.auth
        # a signed enrollment token, see ulrmm.auth.EnrollmentAuthentication
        if isinstance(token, Deployment):
            return site_id is None or token.site_id == site_id
        if not isinstance(token, AuthToken):
            return False
        deploy = token.deploytokens.all()
        installers = token.installertokens.all()
        if site_id is not None:
            deploy = deploy.filter(site_id=site_id)
            installers = installers.filter(site_id=site_id)
        return deploy.exists() or installers.exists()

    if not _has_perm(request, "can_install_agents"):
        return False
    if site_id is not None:
        return _has_perm_on_site(user, site_id)
    return True


def _audit_log_filter(user) -> Q:
    role = _role(user)
    if _is_super(user, role) or not role:
        return Q()

    clients, sites, restricted = _restrictions(role)
    if not restricted:
        return Q()

    agent_ids = list(
        Agent.objects.filter(
            Q(site__client__in=clients) | Q(site__in=sites)
        ).values_list("agent_id", flat=True)
    )
    return Q(agent_id__in=agent_ids) | Q(agent_id=None, username=user.username)


_PATCH_POLICY_EXCLUDE = (
    "id",
    "agent",
    "policy",
    "created_by",
    "created_time",
    "modified_by",
    "modified_time",
)


def _patch_policy_snapshot(pks: list) -> dict:
    snapshot = {}
    for agent in Agent.objects.filter(pk__in=pks).order_by("pk"):
        policy = agent.get_patch_policy()
        snapshot[agent.pk] = {
            field.name: getattr(policy, field.attname)
            for field in policy._meta.fields
            if field.name not in _PATCH_POLICY_EXCLUDE
        }
    return snapshot


@contextmanager
def _patch_policy_guard(request, agents):
    if _has_perm(request, "can_manage_patch_policies"):
        yield
        return

    pks = list(agents.values_list("pk", flat=True))
    with transaction.atomic():
        before = _patch_policy_snapshot(pks)
        yield
        after = _patch_policy_snapshot(pks)
        if before != after:
            raise PermissionDenied("You cannot change patch policies.")
