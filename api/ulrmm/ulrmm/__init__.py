# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from __future__ import absolute_import, unicode_literals

from .celery import app as celery_app

# drf auto-registers this as an authentication method when imported
from .schema import APIAuthenticationScheme  # noqa

__all__ = ("celery_app",)
