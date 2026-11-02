# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from typing import Optional

from django.db import models
from django.db.models import Q


def _or(parts: list[Q]) -> Optional[Q]:
    combined: Optional[Q] = None
    for part in parts:
        combined = part if combined is None else combined | part
    return combined


class PermissionQuerySet(models.QuerySet):
    """Narrows a queryset to the clients and sites a user's role may see.

    Installed as ``objects = PermissionQuerySet.as_manager()`` on the scoped
    models, so ``filter_by_role`` must work both on a bare manager and on any
    chained or related-manager queryset.
    """

    def filter_by_role(self, user) -> "models.QuerySet":
        role = getattr(user, "role", None)

        # superusers (by flag or role) see everything, untouched
        if user.is_superuser or (role and role.is_superuser):
            return self
        # a user without a role sees nothing
        if not role:
            return self.none()

        can_view_clients = role.can_view_clients.all()
        can_view_sites = role.can_view_sites.all()
        has_clients = bool(can_view_clients)
        has_sites = bool(can_view_sites)

        model_name = self.model._meta.label.split(".", 1)[1]

        if model_name in ("Agent", "Deployment", "NetworkDevice"):
            parts = []
            if has_clients:
                parts.append(Q(site__client__in=can_view_clients))
            if has_sites:
                parts.append(Q(site__in=can_view_sites))
            combined = _or(parts)
            return self if combined is None else self.filter(combined)

        if model_name == "Client" and (has_clients or has_sites):
            site_client_pks = can_view_sites.values_list("client_id", flat=True)
            combined = Q(pk__in=site_client_pks) | Q(pk__in=can_view_clients)
            return self.filter(combined)

        if model_name == "Site" and (has_sites or has_clients):
            combined = Q(client__in=can_view_clients) | Q(pk__in=can_view_sites)
            return self.filter(combined)

        if model_name == "Alert":
            parts = []
            if has_clients:
                parts.append(
                    Q(agent__site__client__in=can_view_clients)
                    | Q(network_device__site__client__in=can_view_clients)
                )
            if has_sites:
                parts.append(
                    Q(agent__site__in=can_view_sites)
                    | Q(network_device__site__in=can_view_sites)
                )
            if has_clients or has_sites:
                # custom alerts (no agent/check/task/device) are visible to all
                parts.append(
                    Q(
                        agent__isnull=True,
                        assigned_check__isnull=True,
                        assigned_task__isnull=True,
                        network_device__isnull=True,
                    )
                )
            combined = _or(parts)
            return self if combined is None else self.filter(combined)

        # generic models: filterable only when they carry an agent
        if not hasattr(self.model, "agent"):
            return self
        if not (has_clients or has_sites):
            return self

        parts = []
        if has_clients:
            parts.append(Q(agent__site__client__in=can_view_clients))
        if has_sites:
            parts.append(Q(agent__site__in=can_view_sites))
        # policy checks/tasks count when the policy reaches an agent in scope
        if model_name in ("Check", "AutomatedTask"):
            from ulrmm.permissions import _policy_ids_in_scope

            policy_ids = _policy_ids_in_scope(can_view_clients, can_view_sites)
            parts.append(Q(agent__isnull=True, policy_id__in=policy_ids))
        # no agent-less debug lines here, they often name other tenants
        combined = _or(parts)
        return self if combined is None else self.filter(combined)
