# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.db import models

from agents.models import Agent


class Sample(models.Model):
    # the (agent, ts) index below covers lookups by agent
    agent = models.ForeignKey(
        Agent,
        related_name="metric_samples",
        on_delete=models.CASCADE,
        db_index=False,
    )
    ts = models.DateTimeField()
    cpu = models.FloatField(null=True)
    # megabytes
    mem_used = models.PositiveIntegerField(null=True)
    mem_total = models.PositiveIntegerField(null=True)
    # {mount: used percent}
    disks = models.JSONField(default=dict)
    # {series key: value} from the agent's state push, see metrics.state
    values = models.JSONField(default=dict)

    class Meta:
        indexes = [models.Index(fields=["agent", "ts"])]


class AgentState(models.Model):
    """Latest cleaned state document of an agent."""

    agent = models.OneToOneField(
        Agent, primary_key=True, on_delete=models.CASCADE, related_name="state"
    )
    # server clock; the agent's clock is not trusted
    received = models.DateTimeField()
    agent_ts = models.DateTimeField(null=True)
    data = models.JSONField(default=dict)
