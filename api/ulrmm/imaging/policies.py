# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.db import transaction
from django.db.models import Prefetch
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import serializers
from rest_framework.decorators import api_view
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.response import Response

from accounts.utils import has_superuser_rights
from agents.models import Agent
from clients.models import Client, Site
from core.utils import stepup_denied
from groups.models import DeviceGroup, Tag
from scripts.models import Script
from ulrmm.permissions import _is_restricted, _restrictions, _role, agent_perm_check

from . import resolver
from .models import (
    LINUX_FILES_METHOD,
    SELECTABLE_KINDS,
    BackupPolicy,
    DeviceBackupState,
    PolicyScope,
    Profile,
)
from .serializers import ENFORCEABLE, ConfigSerializer, HookConfirmSerializer
from .service import (
    audit,
    capability,
    covers,
    has_flag,
    keyed_hooks,
    masked_hooks,
    script_hash,
    suspended_hooks,
)

SCOPE_KEYS = ("client", "site", "group", "tag")
WARNINGS_SHOWN = 100


class PolicyInput(serializers.Serializer):
    name = serializers.CharField(max_length=100)
    scope = serializers.ChoiceField(choices=PolicyScope.choices)
    client = serializers.PrimaryKeyRelatedField(
        queryset=Client.objects.all(), allow_null=True, default=None
    )
    site = serializers.PrimaryKeyRelatedField(
        queryset=Site.objects.all(), allow_null=True, default=None
    )
    group = serializers.PrimaryKeyRelatedField(
        queryset=DeviceGroup.objects.all(), allow_null=True, default=None
    )
    tag = serializers.PrimaryKeyRelatedField(
        queryset=Tag.objects.all(), allow_null=True, default=None
    )
    priority = serializers.IntegerField(min_value=-1000, max_value=1000, default=0)
    config = ConfigSerializer()
    enforced = serializers.ListField(
        child=serializers.ChoiceField(choices=ENFORCEABLE), default=list
    )
    agents = serializers.ListField(
        child=serializers.CharField(max_length=200), max_length=500, default=list
    )
    keep_hooks = serializers.BooleanField(default=False)

    def validate(self, data):
        scope = data["scope"]
        if any(bool(data[k]) != (k == scope) for k in SCOPE_KEYS):
            raise ValidationError(
                {"scope": ["Choose exactly the object of this scope."]}
            )
        stored = self.context.get("stored")
        # a stored assigned policy may give back its last device
        if (scope != "assigned" and data["agents"]) or (
            scope == "assigned"
            and not data["agents"]
            and not (stored and stored.scope == "assigned")
        ):
            raise ValidationError(
                {"agents": ["Choose the devices of an assigned policy only."]}
            )
        present = set(data["config"]) | self.context.get("kept", set())
        if not set(data["enforced"]) <= present:
            raise ValidationError(
                {"enforced": ["Enforce only settings this policy sets."]}
            )
        return data


def caller(user):
    """The caller's rights, read once, so a list costs no query per policy."""
    role = _role(user)
    clients, sites, restricted = _restrictions(role) if role else ((), (), False)
    clients = {c.pk for c in clients}
    return {
        "super": has_superuser_rights(user),
        "restricted": _is_restricted(user),
        "clients": clients,
        # a site of a client the role holds counts as held
        "sites": {s.pk for s in sites}
        | (
            set(Site.objects.filter(client__in=clients).values_list("pk", flat=True))
            if restricted
            else set()
        ),
        "check": agent_perm_check(user),
        "manage": has_flag(user, "can_manage_images"),
        "scripts": has_flag(user, "can_run_scripts"),
    }


def editable(user, policy, ctx=None):
    ctx = ctx or caller(user)
    if ctx["super"]:
        return True
    assignments = list(policy.profile_set.all())
    if not assignments:
        return policy.owner_id == user.pk
    return ctx["manage"] and all(ctx["check"](p.agent) for p in assignments)


def may_save(user, scope, key, policy=None, agents=(), ctx=None):
    """The scope rights of contract 3.4."""
    ctx = ctx or caller(user)
    if ctx["super"]:
        return True
    if scope in ("global", "group", "tag"):
        return not ctx["restricted"]
    if scope == "client":
        return not ctx["restricted"] or key in ctx["clients"]
    if scope == "site":
        return not ctx["restricted"] or key in ctx["sites"]
    return (policy is None or editable(user, policy, ctx)) and all(
        ctx["manage"] and ctx["check"](a) for a in agents
    )


def may_run_hooks(user, scope, agents, ctx=None):
    """The hook rights of contract 11.2, step-up aside; an assigned policy
    without devices still needs the script right."""
    ctx = ctx or caller(user)
    if not ctx["scripts"]:
        return False
    if scope == "assigned":
        return ctx["super"] or all(ctx["check"](a) for a in agents)
    return ctx["super"] or not ctx["restricted"]


def hook_state(policy):
    if policy is None:
        return None
    return {
        "has": "hooks" in policy.config,
        "hooks": policy.config.get("hooks"),
        "enforced": "hooks" in policy.enforced,
        "priority": policy.priority,
        "scope": policy.scope,
        "key": _key(policy),
        "agents": {p.agent for p in policy.profile_set.select_related("agent__site")},
    }


def hook_change(old, new):
    """A save or delete that can change which hooks run where: a stored or
    new hooks key, and a difference in what decides where and how they apply."""
    if not ((old and old["has"]) or (new and new["has"])):
        return False
    if old is None or new is None:
        return True
    return any(
        old[k] != new[k]
        for k in ("has", "hooks", "enforced", "priority", "scope", "key")
    ) or {a.pk for a in old["agents"]} != {a.pk for a in new["agents"]}


def hook_rights(request, old, new):
    """None, or the refusal of a hook change; for an assigned policy every
    stored and every new device counts."""
    states = [x for x in (old, new) if x]
    agents = {a.pk: a for x in states for a in x["agents"]}
    if not all(
        may_run_hooks(request.user, x["scope"], agents.values()) for x in states
    ):
        raise PermissionDenied()
    return stepup_denied(request, "Backup hooks run scripts on devices.")


def _warning(agent, selectors):
    native = capability(agent).get("native") or {}
    if native.get("method") != LINUX_FILES_METHOD:
        return None
    kinds = {v["mount"]: v["kind"] for v in native.get("volumes", [])}
    unmatched = [s for s in selectors if s not in kinds]
    unusable = [s for s in selectors if s in kinds and kinds[s] not in SELECTABLE_KINDS]
    if unmatched or unusable:
        return {
            "agent_id": agent.agent_id,
            "hostname": agent.hostname,
            "unmatched": unmatched,
            "unusable": unusable,
        }
    return None


def _check_target(target, scope, key, agents):
    """The target of a policy must cover its whole scope (contract 19.14)."""
    if target["scope"] == "global":
        return
    if scope == "client":
        ok = covers(target, key.pk, None)
    elif scope == "site":
        ok = covers(target, key.client_id, key.pk)
    elif scope == "global":
        ok = False
    else:
        if scope == "assigned":
            devices = agents
        elif scope == "group":
            devices = key.agents().select_related("site")
        else:
            devices = key.agents.select_related("site")
        missing = sorted(
            a.hostname
            for a in devices
            if not covers(target, a.site.client_id, a.site_id)
        )
        if missing:
            raise ValidationError(
                {
                    "config": {
                        "target": [
                            f"Backup target {target['name']} does not cover {', '.join(missing)}."
                        ]
                    }
                }
            )
        return
    if not ok:
        raise ValidationError(
            {
                "config": {
                    "target": [
                        f"Backup target {target['name']} does not cover the scope of this policy."
                    ]
                }
            }
        )


def _key(policy):
    return getattr(policy, f"{policy.scope}_id") if policy.scope in SCOPE_KEYS else None


def policy_row(p, reached, user, ctx=None, scripts_by_id=None):
    agents = [pr.agent for pr in p.profile_set.all()]
    config = dict(p.config)
    scripts = may_run_hooks(user, p.scope, agents, ctx)
    if "hooks" in config:
        config["hooks"] = masked_hooks(config["hooks"], scripts, scripts_by_id)
    target = getattr(p, p.scope) if p.scope in SCOPE_KEYS else None
    return {
        "id": p.pk,
        "name": p.name,
        "scope": p.scope,
        "client": p.client_id,
        "site": p.site_id,
        "group": p.group_id,
        "tag": p.tag_id,
        "priority": p.priority,
        "config": config,
        "enforced": p.enforced,
        "created_at": p.created_at,
        "hooks_approved_by": (
            p.hooks_approved_by.username if p.hooks_approved_by else None
        ),
        "hooks_approved_at": p.hooks_approved_at,
        "hooks_suspended": suspended_hooks(
            p.config.get("hooks", []),
            p.hooks_pinned,
            {"level": p.scope, "id": p.pk},
            scripts_by_id,
        ),
        "agents": [a.agent_id for a in agents] if p.scope == "assigned" else [],
        "reach": len(reached),
        "can_run_scripts": scripts,
        "scope_name": target.name if target else "",
    }


@api_view(["GET", "POST", "PUT", "DELETE"])
@transaction.atomic
def policies(request, pk=None):
    user = request.user
    if not has_flag(user, "can_manage_images"):
        raise PermissionDenied()
    if request.method == "GET":
        resolver.global_policy()
        tab = resolver.table()
        # every read once for the whole list, never per policy
        ctx = caller(user)
        reach = resolver.reach_context()
        groups = resolver.group_sets() if tab["group"] else {}
        rows = list(
            BackupPolicy.objects.select_related(
                "hooks_approved_by", "client", "site", "group", "tag"
            )
            .prefetch_related(
                Prefetch(
                    "profile_set",
                    queryset=Profile.objects.select_related("agent__site"),
                )
            )
            .order_by("name", "pk")
        )
        scripts = Script.objects.in_bulk(
            [h["script_id"] for p in rows for h in p.config.get("hooks", [])]
        )
        return Response(
            [
                policy_row(
                    p,
                    resolver.reach(p, groups=groups, ctx=reach),
                    user,
                    ctx,
                    scripts,
                )
                for p in rows
                if may_save(
                    user,
                    p.scope,
                    _key(p),
                    p if p.scope == "assigned" else None,
                    ctx=ctx,
                )
            ]
        )
    if pk is None and request.method != "POST":
        return Response(status=405)
    policy = None
    if pk is not None:
        policy = get_object_or_404(BackupPolicy.objects.select_for_update(), pk=pk)
        if not may_save(
            user,
            policy.scope,
            _key(policy),
            policy if policy.scope == "assigned" else None,
        ):
            raise PermissionDenied()
    if request.method == "DELETE":
        if policy.scope == "global":
            return Response(
                {"detail": "The global default cannot be deleted."}, status=409
            )
        if policy.profile_set.exists():
            return Response(
                {"detail": "Remove all devices from this policy before deleting it."},
                status=409,
            )
        if hook_change(hook_state(policy), None) and (
            denied := hook_rights(request, hook_state(policy), None)
        ):
            return denied
        before = resolver.reach(policy)
        policy.delete()
        resolver.invalidate()
        resolver.resolve_many(before, cause="policy", author=user)
        audit(None, user.username, f"Backup policy {pk} deleted.")
        return Response(status=204)
    body = request.data if isinstance(request.data, dict) else {}
    kept = set()
    if body.get("keep_hooks") is True and policy is not None:
        # the stored hooks stay as they are, so the request's copy is not validated
        if isinstance(body.get("config"), dict):
            body = {
                **body,
                "config": {k: v for k, v in body["config"].items() if k != "hooks"},
            }
        kept = {"hooks"} & set(policy.config)
    data = PolicyInput(data=body, context={"stored": policy, "kept": kept})
    data.is_valid(raise_exception=True)
    data = data.validated_data
    scope = data["scope"]
    if policy is not None and policy.scope == "global" and scope != "global":
        raise ValidationError({"scope": ["The global default stays global."]})
    key = data[scope] if scope in SCOPE_KEYS else None
    if scope in ("global", "client", "site"):
        taken = BackupPolicy.objects.filter(
            scope=scope, **({scope: key} if key else {})
        ).exclude(pk=pk)
        if taken.exists():
            raise ValidationError(
                {"scope": ["This scope has a backup policy already."]}
            )
    ids = set(data["agents"])
    agents = list(
        Agent.objects.select_for_update().filter(agent_id__in=ids).order_by("pk")
    )
    if len(agents) != len(ids) or not may_save(
        user,
        scope,
        getattr(key, "pk", None),
        policy if scope == "assigned" else None,
        agents,
    ):
        raise PermissionDenied()
    lacking = [
        a.hostname
        for a in agents
        if not (found := capability(a)).get("native") or not found["supported"]
    ]
    if lacking:
        more = f" and {len(lacking) - 10} more" if len(lacking) > 10 else ""
        raise ValidationError(
            "Review an available native backup source for every selected device: "
            f"{', '.join(lacking[:10])}{more}."
        )
    config = data["config"]
    # an absent key inherits hooks, an empty list switches them off: both count
    stored_hooks = policy.config.get("hooks") if policy else None
    old_hooks = stored_hooks or []
    if data["keep_hooks"]:
        if policy is None:
            raise ValidationError({"keep_hooks": ["Only a saved policy keeps hooks."]})
        # the stored hooks stay with their pins and approval
        config.pop("hooks", None)
        if stored_hooks is not None:
            config["hooks"] = stored_hooks
    elif "hooks" in config:
        config["hooks"] = keyed_hooks(config["hooks"], (old_hooks,), "config")
    if "target" in config:
        _check_target(resolver.table()["targets"][config["target"]], scope, key, agents)
    before = resolver.reach(policy) if policy else set()
    old = hook_state(policy)
    new = {
        "has": "hooks" in config,
        "hooks": config.get("hooks"),
        "enforced": "hooks" in data["enforced"],
        "priority": data["priority"],
        "scope": scope,
        "key": getattr(key, "pk", None),
        "agents": set(agents),
    }
    hooks_change = hook_change(old, new)
    if hooks_change and (denied := hook_rights(request, old, new)):
        return denied
    # a device taken from another assigned policy that holds hooks changes its hooks
    taken = [
        p.agent
        for p in Profile.objects.filter(agent__in=agents)
        .exclude(policy=None)
        .exclude(policy=policy)
        .select_related("policy", "agent__site")
        if "hooks" in p.policy.config
    ]
    if taken and not hooks_change:
        if not may_run_hooks(user, "assigned", taken):
            raise PermissionDenied()
        if denied := stepup_denied(request, "Backup hooks run scripts on devices."):
            return denied
    policy = policy or BackupPolicy(owner=user)
    policy.name = data["name"]
    policy.scope = scope
    for k in SCOPE_KEYS:
        setattr(policy, k, data[k])
    policy.priority = data["priority"]
    policy.config = config
    policy.enforced = data["enforced"]
    if hooks_change:
        scripts = Script.objects.in_bulk(
            [h["script_id"] for h in config.get("hooks", [])]
        )
        # a kept pin stays, so a script edited after its pin stays suspended
        old = policy.hooks_pinned
        policy.hooks_pinned = {
            str(pk): old.get(str(pk)) or script_hash(s) for pk, s in scripts.items()
        }
        policy.hooks_approved_by = user
        policy.hooks_approved_at = timezone.now()
    policy.save()
    # the agent list replaces the assignment; editable() covered the removed devices
    removed = Profile.objects.filter(policy=policy).select_related("agent")
    if scope == "assigned":
        removed = removed.exclude(agent__in=agents)
    for profile in removed:
        Profile.objects.filter(pk=profile.pk).update(policy=None)
        audit(profile.agent, user.username, f"Backup policy {policy.pk} removed.")
    for agent in agents:
        profile, _ = resolver.rows(agent)
        Profile.objects.filter(pk=profile.pk).update(policy=policy, operator=user)
        audit(agent, user.username, f"Backup policy {policy.pk} applied.")
    resolver.invalidate()
    after = resolver.reach(policy)
    resolver.resolve_many(before | after, cause="policy", author=user)
    audit(None, user.username, f"Backup policy {policy.pk} ({scope}) saved.")
    reached = Agent.objects.filter(pk__in=after).order_by("pk")
    warnings = [w for a in reached if (w := _warning(a, config.get("volumes", [])))]
    if config.get("hooks"):
        legacy = set(
            DeviceBackupState.objects.filter(agent__in=after, protocol=0).values_list(
                "agent_id", flat=True
            )
        )
        warnings += [
            {"agent_id": a.agent_id, "hostname": a.hostname, "legacy": True}
            for a in reached
            if a.pk in legacy
        ]
    return Response(
        {
            "id": policy.pk,
            "warnings": warnings[:WARNINGS_SHOWN],
            "warnings_more": max(0, len(warnings) - WARNINGS_SHOWN),
        },
        status=200 if pk else 201,
    )


@api_view(["POST"])
@transaction.atomic
def hooks_confirm(request, pk):
    user = request.user
    if not has_flag(user, "can_manage_images"):
        raise PermissionDenied()
    policy = get_object_or_404(BackupPolicy.objects.select_for_update(), pk=pk)
    assigned = policy.scope == "assigned"
    agents = [p.agent for p in policy.profile_set.select_related("agent")]
    if not may_save(
        user, policy.scope, _key(policy), policy if assigned else None
    ) or not may_run_hooks(user, policy.scope, agents):
        raise PermissionDenied()
    if denied := stepup_denied(request, "Backup hooks run scripts on devices."):
        return denied
    data = HookConfirmSerializer(data=request.data)
    data.is_valid(raise_exception=True)
    data = data.validated_data
    if not any(
        h["script_id"] == data["script_id"] for h in policy.config.get("hooks", [])
    ):
        raise ValidationError({"script_id": ["This policy holds no such hook."]})
    script = Script.objects.filter(pk=data["script_id"]).first()
    if script is None or script_hash(script) != data["sha256"]:
        return Response(
            {"detail": "The script changed again; review it again."}, status=409
        )
    policy.hooks_pinned = {**policy.hooks_pinned, str(script.pk): data["sha256"]}
    policy.hooks_approved_by = user
    policy.hooks_approved_at = timezone.now()
    policy.save(
        update_fields=["hooks_pinned", "hooks_approved_by", "hooks_approved_at"]
    )
    resolver.invalidate()
    reached = resolver.reach(policy)
    resolver.resolve_many(reached, cause="policy", author=user)
    audit(
        None,
        user.username,
        f"Backup hook {script.name} of policy {pk} confirmed at {data['sha256'][:12]}.",
    )
    return Response(policy_row(policy, reached, user))
