# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Preview and import of a source's snapshot.

Nothing that exists is overwritten: clients and sites are matched by name,
custom fields by model and name, scripts by name and shell, snippets and
keystore entries by name. Matched rows keep their values; only empty custom
field values are filled in. Running an import twice adds nothing."""

from django.db import transaction
from django.utils import timezone as djangotime

from clients.models import Client, Site
from core.models import CustomField, GlobalKVStore
from scripts.models import Script, ScriptSnippet

from . import link
from .models import ImportedDevice

PARTS = ("clients", "custom_fields", "scripts", "snippets", "keystore", "devices")
# names listed per part in the preview
SHOWN = 200


def _key(*names) -> tuple:
    return tuple(n.lower() for n in names)


def _existing():
    sites = {
        _key(client, site)
        for client, site in Site.objects.values_list("client__name", "name")
    }
    return {
        "clients": {_key(n) for n in Client.objects.values_list("name", flat=True)},
        "sites": sites,
        "custom_fields": {
            _key(m, n) for m, n in CustomField.objects.values_list("model", "name")
        },
        "scripts": {_key(n, s) for n, s in Script.objects.values_list("name", "shell")},
        "snippets": {
            _key(n) for n in ScriptSnippet.objects.values_list("name", flat=True)
        },
        "keystore": {
            _key(n) for n in GlobalKVStore.objects.values_list("name", flat=True)
        },
    }


def _site_names(snapshot) -> dict:
    # site ref -> (client name, site name)
    return {
        s["ref"]: (c["name"], s["name"])
        for c in snapshot.get("clients", [])
        for s in c["sites"]
        if s["ref"]
    }


def _part(names: list[str], new: list[str]) -> dict:
    return {"total": len(names), "new_count": len(new), "new": new[:SHOWN]}


def plan(source) -> dict:
    snap, have = source.snapshot or {}, _existing()
    clients = snap.get("clients", [])
    sites = [(c["name"], s["name"]) for c in clients for s in c["sites"]]
    fields = snap.get("custom_fields", [])
    scripts = snap.get("scripts", [])
    snippets = snap.get("snippets", [])
    keystore = snap.get("keystore", [])
    devices = snap.get("devices", [])
    known = set(source.devices.values_list("ref", flat=True))
    site_names = _site_names(snap)
    return {
        "clients": _part(
            [c["name"] for c in clients],
            [c["name"] for c in clients if _key(c["name"]) not in have["clients"]],
        ),
        "sites": _part(
            [f"{c} / {s}" for c, s in sites],
            [f"{c} / {s}" for c, s in sites if _key(c, s) not in have["sites"]],
        ),
        "custom_fields": _part(
            [f"{f['model']}: {f['name']}" for f in fields],
            [
                f"{f['model']}: {f['name']}"
                for f in fields
                if _key(f["model"], f["name"]) not in have["custom_fields"]
            ],
        ),
        "scripts": _part(
            [s["name"] for s in scripts],
            [
                s["name"]
                for s in scripts
                if _key(s["name"], s["shell"]) not in have["scripts"]
            ],
        ),
        "snippets": _part(
            [s["name"] for s in snippets],
            [s["name"] for s in snippets if _key(s["name"]) not in have["snippets"]],
        ),
        "keystore": _part(
            [k["name"] for k in keystore],
            [k["name"] for k in keystore if _key(k["name"]) not in have["keystore"]],
        ),
        "devices": {
            **_part(
                [d["hostname"] for d in devices],
                [d["hostname"] for d in devices if d["ref"] not in known],
            ),
            # devices whose site is not in the snapshot cannot be placed
            "without_site": sum(1 for d in devices if d["site_ref"] not in site_names),
        },
    }


def _import_clients(snap, done):
    clients = {c.name.lower(): c for c in Client.objects.all()}
    for c in snap.get("clients", []):
        client = clients.get(c["name"].lower())
        if client is None:
            client = Client(name=c["name"])
            client.save()
            clients[client.name.lower()] = client
            done["clients"] += 1
        link.fill(client, "client", c["custom_fields"])
        sites = {s.name.lower(): s for s in client.sites.all()}
        for s in c["sites"]:
            site = sites.get(s["name"].lower())
            if site is None:
                site = Site(client=client, name=s["name"])
                site.save()
                done["sites"] += 1
            link.fill(site, "site", s["custom_fields"])


def _import_fields(snap, done):
    have = {_key(m, n) for m, n in CustomField.objects.values_list("model", "name")}
    for f in snap.get("custom_fields", []):
        if _key(f["model"], f["name"]) in have:
            continue
        CustomField(
            model=f["model"], name=f["name"], type=f["type"], options=f["options"]
        ).save()
        have.add(_key(f["model"], f["name"]))
        done["custom_fields"] += 1


def _import_scripts(snap, done):
    have = {_key(n, s) for n, s in Script.objects.values_list("name", "shell")}
    for s in snap.get("scripts", []):
        if _key(s["name"], s["shell"]) in have:
            continue
        Script(
            name=s["name"],
            description=s["description"],
            shell=s["shell"],
            category=s["category"] or None,
            args=s["args"],
            env_vars=s["env_vars"],
            script_body=s["body"],
            default_timeout=s["timeout"],
            supported_platforms=s["platforms"],
            run_as_user=s["run_as_user"],
            syntax=s["syntax"] or None,
        ).save()
        have.add(_key(s["name"], s["shell"]))
        done["scripts"] += 1


def _import_snippets(snap, done):
    have = {_key(n) for n in ScriptSnippet.objects.values_list("name", flat=True)}
    for s in snap.get("snippets", []):
        if _key(s["name"]) in have:
            continue
        ScriptSnippet(
            name=s["name"], desc=s["desc"], code=s["code"], shell=s["shell"]
        ).save()
        have.add(_key(s["name"]))
        done["snippets"] += 1


def _import_keystore(snap, done):
    have = {_key(n) for n in GlobalKVStore.objects.values_list("name", flat=True)}
    for k in snap.get("keystore", []):
        if _key(k["name"]) in have:
            continue
        GlobalKVStore(name=k["name"], value=k["value"]).save()
        have.add(_key(k["name"]))
        done["keystore"] += 1


def _import_devices(source, snap, done):
    site_names = _site_names(snap)
    sites = {
        _key(s.client.name, s.name): s for s in Site.objects.select_related("client")
    }
    for d in snap.get("devices", []):
        names = site_names.get(d["site_ref"])
        site = sites.get(_key(*names)) if names else None
        _, created = ImportedDevice.objects.update_or_create(
            source=source,
            ref=d["ref"],
            defaults={
                "site": site,
                "hostname": d["hostname"],
                "serial": d["serial"],
                "plat": d["plat"],
                "goarch": d["goarch"],
                "monitoring_type": d["monitoring_type"],
                "os_name": d["os_name"],
                "data": {
                    "description": d["description"],
                    "notes": d["notes"],
                    "custom_fields": d["custom_fields"],
                },
            },
        )
        done["devices"] += int(created)


def run(source, parts) -> dict:
    """Imports the chosen parts of the snapshot in one transaction and links
    the devices to agents that are already enrolled."""
    snap = source.snapshot or {}
    done = dict.fromkeys((*PARTS, "sites", "linked"), 0)
    parts = set(parts)
    with transaction.atomic():
        # fields first: client, site and device values need them
        if "custom_fields" in parts:
            _import_fields(snap, done)
        if "clients" in parts:
            _import_clients(snap, done)
        if "scripts" in parts:
            _import_scripts(snap, done)
        if "snippets" in parts:
            _import_snippets(snap, done)
        if "keystore" in parts:
            _import_keystore(snap, done)
        if "devices" in parts:
            _import_devices(source, snap, done)
        source.last_import = djangotime.now()
        type(source).objects.filter(pk=source.pk).update(last_import=source.last_import)
    if "devices" in parts:
        done["linked"] = link.link_source(source)
    return done
