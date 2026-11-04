# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from typing import TYPE_CHECKING, Optional

from django.core.cache import cache
from django.db import models
from django.db.models import Q, QuerySet

from logs.models import BaseAuditModel
from ulrmm.constants import CORESETTINGS_CACHE_KEY, AgentMonType, AgentPlat, CheckType

if TYPE_CHECKING:
    from agents.models import Agent
    from autotasks.models import AutomatedTask
    from checks.models import Check

# order of the merged list the agent receives
CHECK_GROUPS = (
    "disk",
    "ping",
    "cpu",
    "memory",
    "winsvc",
    "script",
    "eventlog",
    "systemd",
    "container",
    "metric",
)
HEALTH = "health"


def _check_key(check: "Check", agent: "Agent"):
    """(group, identity) of a policy or agent check, None when the check does not
    run on this agent's platform."""
    kind = check.check_type
    windows = agent.plat == AgentPlat.WINDOWS
    if kind == CheckType.DISK_SPACE:
        # drive letter on windows, mount point on posix
        return "disk", check.disk
    if kind == CheckType.PING:
        return "ping", check.ip
    if kind == CheckType.CPU_LOAD:
        return "cpu", None
    if kind == CheckType.MEMORY:
        return "memory", None
    if kind in (CheckType.SECURITY, CheckType.HW_HEALTH):
        return HEALTH, kind
    if kind == CheckType.WINSVC and windows:
        return "winsvc", check.svc_name
    if kind == CheckType.SCRIPT and check.script:
        if agent.is_supported_script(check.script.supported_platforms):
            return "script", check.script_id
        return None
    if kind == CheckType.EVENT_LOG and windows:
        return "eventlog", (check.log_name, check.event_id)
    if kind == CheckType.SYSTEMD and agent.plat in (AgentPlat.LINUX, AgentPlat.FREEBSD):
        return "systemd", check.svc_name
    if kind == CheckType.CONTAINER:
        return "container", (check.container_kind, check.container)
    if kind == CheckType.METRIC:
        labels = check.metric_labels if isinstance(check.metric_labels, dict) else {}
        pairs = sorted((str(k), str(v)) for k, v in labels.items())
        return "metric", (check.metric, tuple(pairs))
    return None


class Policy(BaseAuditModel):
    name = models.CharField(max_length=255, unique=True)
    desc = models.CharField(max_length=255, null=True, blank=True)
    active = models.BooleanField(default=False)
    enforced = models.BooleanField(default=False)
    alert_template = models.ForeignKey(
        "alerts.AlertTemplate",
        related_name="policies",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )
    excluded_sites = models.ManyToManyField(
        "clients.Site", related_name="policy_exclusions", blank=True
    )
    excluded_clients = models.ManyToManyField(
        "clients.Client", related_name="policy_exclusions", blank=True
    )
    excluded_agents = models.ManyToManyField(
        "agents.Agent", related_name="policy_exclusions", blank=True
    )

    def __str__(self) -> str:
        return self.name

    def save(self, *args, **kwargs) -> None:
        from alerts.tasks import cache_agents_alert_template

        old = type(self).objects.filter(pk=self.pk).first() if self.pk else None
        super().save(old, *args, **kwargs)
        if old is None:
            return

        template_changed = old.alert_template_id != self.alert_template_id
        if template_changed or (self.alert_template_id and old.active != self.active):
            cache_agents_alert_template.delay()
        if old.active != self.active or old.enforced != self.enforced:
            self.forget_cached_policies()

    def delete(self, *args, **kwargs):
        self.forget_cached_policies()
        return super().delete(*args, **kwargs)

    @staticmethod
    def forget_cached_policies() -> None:
        """Drop the per-agent merges of policy checks and tasks."""
        cache.delete(CORESETTINGS_CACHE_KEY)
        cache.delete_many_pattern("agent_*")

    @property
    def is_default_server_policy(self) -> bool:
        return self.default_server_policy.exists()  # type: ignore

    @property
    def is_default_workstation_policy(self) -> bool:
        return self.default_workstation_policy.exists()  # type: ignore

    def is_agent_excluded(self, agent: "Agent") -> bool:
        # works on the prefetched relations of Agent.get_agent_policies
        return (
            any(a.pk == agent.pk for a in self.excluded_agents.all())
            or any(s.pk == agent.site_id for s in self.excluded_sites.all())
            or any(c.pk == agent.site.client_id for c in self.excluded_clients.all())
        )

    def related_agents(self, mon_type: Optional[str] = None) -> "QuerySet[Agent]":
        """Agents this policy applies to at any level, active or not: the
        same answer as Agent.get_agent_policies, as one query."""
        from agents.models import Agent
        from core.models import CoreSettings

        kinds = AgentMonType.values
        # one lookup for both default slots
        slots = CoreSettings.objects.values_list(*(f"{k}_policy_id" for k in kinds))
        defaults = {k for row in slots for k, pk in zip(kinds, row) if pk == self.pk}
        reach = Q(policy=self)
        for kind in kinds:
            free = Q(monitoring_type=kind, block_policy_inheritance=False)
            reach |= free & Q(**{f"site__{kind}_policy": self})
            free &= Q(site__block_policy_inheritance=False)
            reach |= free & Q(**{f"site__client__{kind}_policy": self})
            if kind in defaults:
                reach |= free & Q(site__client__block_policy_inheritance=False)

        agents = (
            Agent.objects.filter(reach)
            .exclude(pk__in=self.excluded_agents.values("pk"))
            .exclude(site__in=self.excluded_sites.values("pk"))
            .exclude(site__client__in=self.excluded_clients.values("pk"))
        )
        if mon_type:
            agents = agents.filter(monitoring_type=mon_type)
        return agents

    @staticmethod
    def serialize(policy: "Policy") -> dict:
        from . import serializers

        return serializers.PolicyAuditSerializer(policy).data

    @staticmethod
    def _active_policies(agent: "Agent") -> "list[Policy]":
        found: dict[int, Policy] = {}
        for policy in agent.get_agent_policies().values():
            if policy and policy.active:
                found.setdefault(policy.pk, policy)
        return list(found.values())

    @staticmethod
    def get_policy_tasks(agent: "Agent") -> "list[AutomatedTask]":
        return [
            task
            for policy in Policy._active_policies(agent)
            for task in policy.autotasks.all()
            if agent.plat in task.task_supported_platforms
        ]

    @staticmethod
    def get_policy_checks(agent: "Agent") -> "list[Check]":
        from checks.models import Check

        # pk order makes the first of two equal checks the one that wins
        agent_checks = list(agent.agentchecks.order_by("pk"))
        enforced: list[Check] = []
        others: list[Check] = []
        for policy in Policy._active_policies(agent):
            (enforced if policy.enforced else others).extend(policy.policychecks.all())
        if not enforced and not others:
            return []

        # enforced policy checks beat the agent's own, the agent's own beat the
        # rest; agent checks never come back, the agent has them already
        groups: dict[str, list[Check]] = {g: [] for g in (*CHECK_GROUPS, HEALTH)}
        seen = set()
        overridden = []
        for check in enforced + agent_checks + others:
            key = _check_key(check, agent)
            if key is None:
                continue
            if key in seen:
                if check.agent_id:
                    overridden.append(check.pk)
                continue
            seen.add(key)
            if not check.agent_id:
                groups[key[0]].append(check)

        if overridden:
            Check.objects.filter(pk__in=overridden).update(overridden_by_policy=True)
        return [check for group in groups.values() for check in group]
