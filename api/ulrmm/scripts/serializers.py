# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from rest_framework import serializers
from rest_framework.exceptions import ValidationError

from ulrmm.constants import AgentPlat

from .models import Script, ScriptSnippet, check_env_vars, clean_variables

ENV_MASK = "********"


def masked_env_vars(env_vars):
    if not env_vars:
        return env_vars
    return [f"{str(e).partition('=')[0]}={ENV_MASK}" for e in env_vars]


def keep_masked_env_vars(submitted, stored):
    """NAME=******** sent back by the web means: keep the stored value."""
    if not isinstance(submitted, list):
        return submitted
    known = {
        e.partition("=")[0]: e for e in stored or [] if isinstance(e, str) and "=" in e
    }
    out = []
    for item in submitted:
        name, sep, value = (
            item.partition("=") if isinstance(item, str) else ("", "", "")
        )
        if sep and value == ENV_MASK:
            if name not in known:
                raise ValidationError(f"{name[:64]} has no stored value to keep.")
            item = known[name]
        out.append(item)
    return out


class _EnvVarsMaskedUnlessRevealed:
    # views pass reveal_env_vars=False for users who only list scripts
    def to_representation(self, instance):
        data = super().to_representation(instance)
        if self.context.get("reveal_env_vars") is False and "env_vars" in data:
            data["env_vars"] = masked_env_vars(data["env_vars"])
        return data


class ScriptTableSerializer(_EnvVarsMaskedUnlessRevealed, serializers.ModelSerializer):
    class Meta:
        model = Script
        fields = list("""
            id name description script_type shell args category favorite
            default_timeout syntax filename hidden supported_platforms run_as_user
            env_vars variables
            """.split())


class ScriptSerializer(_EnvVarsMaskedUnlessRevealed, serializers.ModelSerializer):
    script_hash = serializers.ReadOnlyField()

    class Meta:
        model = Script
        fields = list("""
            id name description shell args category favorite script_body
            script_hash default_timeout syntax filename hidden supported_platforms
            run_as_user env_vars variables
            """.split())
        extra_kwargs = {"script_body": {"trim_whitespace": False}}

    def validate_variables(self, value):
        try:
            return clean_variables(value)
        except ValueError as e:
            raise ValidationError(str(e))

    def validate_env_vars(self, value):
        value = keep_masked_env_vars(value, getattr(self.instance, "env_vars", None))
        check_env_vars(value)
        return value

    def validate_supported_platforms(self, value):
        unknown = set(value or []) - set(AgentPlat.values)
        if unknown:
            raise ValidationError(
                f"{sorted(unknown)[0]} is not a platform, use one of "
                f"{', '.join(AgentPlat.values)}"
            )
        return value


class ScriptCheckSerializer(serializers.ModelSerializer):
    code = serializers.ReadOnlyField()
    script_hash = serializers.ReadOnlyField()

    class Meta:
        model = Script
        fields = ["code", "shell", "run_as_user", "env_vars", "script_hash"]


class ScriptSnippetSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScriptSnippet
        fields = ("id", "name", "desc", "code", "shell")
        extra_kwargs = {"code": {"trim_whitespace": False}}
