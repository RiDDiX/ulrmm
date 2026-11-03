# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.apps import AppConfig


class SoftwareConfig(AppConfig):
    name = "software"

    def ready(self):
        from deploy.signals import agent_enrolled

        from .baselines import on_enrolled

        agent_enrolled.connect(on_enrolled, dispatch_uid="software-baselines")
