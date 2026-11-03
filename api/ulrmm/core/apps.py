# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.apps import AppConfig
from django.db import models


def _unique_together_only(self, model):
    # DRF >= 3.16 also turns Meta.constraints into serializer validators and
    # makes their fields required. The API never did that; the database
    # enforces the constraints, so only unique_together is checked here.
    for parent_class in [model] + list(model._meta.parents):
        for unique_together in parent_class._meta.unique_together:
            yield unique_together, model._default_manager, [], None, None, None


class CoreConfig(AppConfig):
    name = "core"

    def ready(self):
        from rest_framework import serializers

        serializers.ModelSerializer.get_unique_together_constraints = (
            _unique_together_only
        )
        # DRF >= 3.17 maps big integer columns to BigIntegerField, which
        # changes the error text; keep the plain IntegerField the API had
        mapping = serializers.ModelSerializer.serializer_field_mapping
        mapping[models.BigAutoField] = serializers.IntegerField
        mapping[models.BigIntegerField] = serializers.IntegerField
