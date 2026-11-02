# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.dispatch import receiver

from ulrmm.constants import AgentPlat

from .signals import agent_enrolled

# the agent needs a moment to start its service and connect
LAPS_DELAY = 5 * 60
# BitLocker may still be encrypting right after setup
KEYS_DELAY = 30 * 60


@receiver(agent_enrolled, dispatch_uid="deploy_laps_after_enroll")
def laps_after_enroll(sender, agent, deployment, **kwargs):
    from laps.models import SCRIPTS, LapsPolicy

    from .tasks import enrolled_laps_task

    policy = LapsPolicy.for_site(agent.site_id)
    if agent.plat in SCRIPTS and policy and policy.enabled:
        enrolled_laps_task.apply_async((agent.pk,), countdown=LAPS_DELAY)


@receiver(agent_enrolled, dispatch_uid="deploy_keys_after_enroll")
def keys_after_enroll(sender, agent, deployment, **kwargs):
    from .tasks import enrolled_keys_task

    if agent.plat == AgentPlat.WINDOWS:
        enrolled_keys_task.apply_async((agent.pk,), countdown=KEYS_DELAY)
