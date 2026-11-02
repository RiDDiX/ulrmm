# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Imported device -> enrolled agent.

A device links to the agent with the same host name (short name, any case)
in its site. Without a site, or when the site has none, a single agent with
that host name anywhere is taken; several are told apart by serial number.
Linking copies the description (if the agent has none), the notes and the
custom field values that are still empty on the agent."""

from django.db import transaction

from agents.models import Agent, AgentCustomField, Note
from core.models import CustomField

from .models import ImportedDevice, MigrateState


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


def apply(device, agent) -> None:
    data = device.data or {}
    with transaction.atomic():
        if data.get("description") and not agent.description:
            Agent.objects.filter(pk=agent.pk).update(description=data["description"])
        for text in data.get("notes", []):
            Note.objects.create(agent=agent, note=text)
        fill(agent, "agent", data.get("custom_fields") or {})
        device.agent = agent
        device.migrate_state = MigrateState.LINKED
        device.migrate_error = ""
        device.save(update_fields=["agent", "migrate_state", "migrate_error"])


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
