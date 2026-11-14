# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Imported device -> enrolled agent.

A device links to the agent with the same host name (short name, any case)
in its site. Without a site, or when the site has none, a single agent with
that host name anywhere is taken; several are told apart by serial number.
Linking copies the description (if the agent has none), the notes and the
custom field values that are still empty on the agent. From a source that
reads them it also takes the device's own checks and tasks, its policy, its
patch policy and its settings, each only where the agent still has the
default or nothing, and the device's exclusions from policies and alert
templates. What cannot be taken is kept in data["link_skipped"]."""

from django.db import transaction

from agents.models import Agent, AgentCustomField, Note
from core.models import CustomField

from . import build
from .models import ImportedDevice, MigrateState

# device-level data the import keeps with the device
DEVICE_KEYS = (
    "policy",
    "patch_policy",
    "settings",
    "checks",
    "tasks",
    "excluded_policies",
    "excluded_templates",
)


def short(hostname: str) -> str:
    return hostname.split(".")[0].strip().lower()


def _candidates(device, agents) -> list:
    name = short(device.hostname)
    same = [a for a in agents if short(a.hostname) == name]
    in_site = [a for a in same if device.site_id and a.site_id == device.site_id]
    if len(in_site) == 1:
        return in_site
    pool = in_site or same
    if len(pool) > 1 and device.serial:
        serial = device.serial.lower()
        pool = [a for a in pool if a.serial_number.strip().lower() == serial]
    return pool


def fill(owner, model: str, values: dict) -> None:
    """Custom field values by field name. A value already set on the owner
    stays; a field the owner has no row for gets one."""
    from clients.models import ClientCustomField, SiteCustomField

    rows = {
        "agent": AgentCustomField,
        "client": ClientCustomField,
        "site": SiteCustomField,
    }[model]
    fields = {f.name.lower(): f for f in CustomField.objects.filter(model=model)}
    for name, value in values.items():
        field = fields.get(name.lower())
        if field is None:
            continue
        row, created = rows.objects.get_or_create(field=field, **{model: owner})
        if created or row.value in (None, "", []):
            if isinstance(value, list):
                value = ",".join(value)
            row.save_to_field(value)


def _settings(agent, data, skip) -> None:
    from agents.views import _AgentEditSerializer
    from automation.models import Policy

    # the dashboard's edit checks, for what is still at its default here
    values = {
        name: value
        for name, value in (data.get("settings") or {}).items()
        if getattr(agent, name) == Agent._meta.get_field(name).get_default()
        and getattr(agent, name) != value
    }
    if data.get("policy"):
        policy = Policy.objects.filter(name__iexact=data["policy"]).order_by("pk")
        if not policy.exists():
            skip(f"policy {data['policy']}", "it is not here")
        elif agent.policy_id is None:
            values["policy"] = policy.first().pk
    for name, value in values.items():
        serializer = _AgentEditSerializer(agent, data={name: value}, partial=True)
        _, why = build.save(serializer)
        if why:
            skip(name, why)


def _exclusions(agent, data) -> None:
    from alerts.models import AlertTemplate
    from automation.models import Policy

    for model, names in (
        (Policy, data.get("excluded_policies")),
        (AlertTemplate, data.get("excluded_templates")),
    ):
        for name in names or []:
            for obj in model.objects.filter(name__iexact=name):
                obj.excluded_agents.add(agent)


def _device_level(agent, data) -> list:
    from autotasks.tasks import create_win_task_schedule

    skipped = []

    def skip(name: str, why: str) -> None:
        skipped.append({"name": name, "reason": why})

    # a fresh row: the matched one carries only a few fields
    agent = Agent.objects.get(pk=agent.pk)
    _settings(agent, data, skip)
    if data.get("patch_policy"):
        build.patch_policy(data["patch_policy"], skip, "patch policy", agent=agent)
    refs, owner = build.Refs(), {"agent": agent.pk}
    made = build.checks(owner, data.get("checks") or [], refs, skip, plat=agent.plat)
    for task in build.tasks(owner, data.get("tasks") or [], refs, made, skip):
        transaction.on_commit(lambda pk=task.pk: create_win_task_schedule.delay(pk=pk))
    _exclusions(agent, data)
    return skipped


def apply(device, agent) -> None:
    data = device.data or {}
    with transaction.atomic():
        if data.get("description") and not agent.description:
            Agent.objects.filter(pk=agent.pk).update(description=data["description"])
        for text in data.get("notes", []):
            Note.objects.create(agent=agent, note=text)
        fill(agent, "agent", data.get("custom_fields") or {})
        if any(data.get(k) for k in DEVICE_KEYS):
            device.data = {**data, "link_skipped": _device_level(agent, data)}
        device.agent = agent
        device.migrate_state = MigrateState.LINKED
        device.migrate_error = ""
        device.save(update_fields=["agent", "migrate_state", "migrate_error", "data"])


def _agents(hostnames):
    # filtered in Python: host names may carry a domain on either side
    wanted = {short(h) for h in hostnames}
    linked = ImportedDevice.objects.exclude(agent=None).values_list("agent_id")
    return [
        a
        for a in Agent.objects.exclude(pk__in=linked).only(
            "pk", "hostname", "site_id", "description", "wmi_detail", "plat"
        )
        if short(a.hostname) in wanted
    ]


def link_source(source) -> int:
    devices = list(source.devices.filter(agent=None))
    agents = _agents(d.hostname for d in devices)
    taken, count = set(), 0
    for device in devices:
        found = [a for a in _candidates(device, agents) if a.pk not in taken]
        if len(found) == 1:
            apply(device, found[0])
            taken.add(found[0].pk)
            count += 1
    return count


def on_enroll(agent) -> None:
    """Called by newagent. Only a device of the agent's own site links here;
    the others wait for a manual link run, so an install in the wrong site
    never takes over another site's data."""
    name = short(agent.hostname)
    devices = [
        d
        for d in ImportedDevice.objects.filter(agent=None, site_id=agent.site_id)
        if short(d.hostname) == name
    ]
    if len(devices) == 1:
        apply(devices[0], agent)
