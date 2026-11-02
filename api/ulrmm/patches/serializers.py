# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from copy import copy

from rest_framework import serializers

from agents.models import Agent
from clients.models import Client, Site

from .models import MaintenanceSchedule, ScheduleFrequency

TARGETS_MAX = 1000
DATES_MAX = 400


class MaintenanceScheduleSerializer(serializers.ModelSerializer):
    dates = serializers.ListField(
        child=serializers.DateField(), max_length=DATES_MAX, required=False
    )
    weekdays = serializers.ListField(
        child=serializers.IntegerField(min_value=0, max_value=6),
        max_length=7,
        required=False,
    )
    month_day = serializers.IntegerField(
        min_value=1, max_value=31, allow_null=True, required=False
    )
    month_week = serializers.ChoiceField(
        choices=[1, 2, 3, 4, -1], allow_null=True, required=False
    )
    month_weekday = serializers.IntegerField(
        min_value=0, max_value=6, allow_null=True, required=False
    )
    # the agent holds a device awake for at most 6 h
    duration = serializers.IntegerField(min_value=5, max_value=360, required=False)
    excluded_dates = serializers.ListField(
        child=serializers.DateField(), max_length=DATES_MAX, required=False
    )
    agents = serializers.ListField(
        child=serializers.CharField(max_length=200),
        max_length=TARGETS_MAX,
        required=False,
    )
    sites = serializers.ListField(
        child=serializers.IntegerField(min_value=1),
        max_length=TARGETS_MAX,
        required=False,
    )
    clients = serializers.ListField(
        child=serializers.IntegerField(min_value=1),
        max_length=TARGETS_MAX,
        required=False,
    )

    class Meta:
        model = MaintenanceSchedule
        fields = "__all__"
        read_only_fields = (
            "created_by",
            "created_time",
            "modified_by",
            "modified_time",
        )

    def validate_run_time(self, value):
        return value.replace(second=0, microsecond=0)

    def validate(self, data):
        # the schedule as it will be saved
        rule = copy(self.instance) if self.instance else MaintenanceSchedule()
        for k, v in data.items():
            setattr(rule, k, v)

        freq = rule.frequency
        if freq == ScheduleFrequency.ONCE and not rule.dates:
            raise serializers.ValidationError("Pick at least one date.")
        if freq == ScheduleFrequency.WEEKLY and not rule.weekdays:
            raise serializers.ValidationError("Pick at least one weekday.")
        if freq == ScheduleFrequency.MONTHLY and not (
            rule.month_day or (rule.month_week and rule.month_weekday is not None)
        ):
            raise serializers.ValidationError(
                "Pick a day of the month or a weekday of the month."
            )
        if rule.start_date and rule.end_date and rule.end_date < rule.start_date:
            raise serializers.ValidationError("The end date is before the start date.")

        # drop what the frequency does not use
        data["dates"] = (
            sorted(set(rule.dates)) if freq == ScheduleFrequency.ONCE else []
        )
        data["weekdays"] = (
            sorted(set(rule.weekdays)) if freq == ScheduleFrequency.WEEKLY else []
        )
        monthly = freq == ScheduleFrequency.MONTHLY
        by_day = monthly and bool(rule.month_day)
        data["month_day"] = rule.month_day if by_day else None
        data["month_week"] = rule.month_week if monthly and not by_day else None
        data["month_weekday"] = rule.month_weekday if monthly and not by_day else None
        data["excluded_dates"] = sorted(set(rule.excluded_dates))

        if self.context.get("preview"):
            return data

        data["agents"] = sorted(set(rule.agents))
        data["sites"] = sorted(set(rule.sites))
        data["clients"] = sorted(set(rule.clients))
        if not (data["agents"] or data["sites"] or data["clients"]):
            raise serializers.ValidationError("Pick at least one target.")
        for model, field, key in (
            (Agent, "agent_id", "agents"),
            (Site, "pk", "sites"),
            (Client, "pk", "clients"),
        ):
            found = model.objects.filter(**{f"{field}__in": data[key]}).count()
            if found != len(data[key]):
                raise serializers.ValidationError(f"Unknown {key} in the targets.")
        return data
