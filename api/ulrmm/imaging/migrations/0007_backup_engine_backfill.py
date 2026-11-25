# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.db import migrations
from django.db.models import F, Max, OuterRef, Subquery
from django.utils import timezone

DEFAULT_TARGET = "images"
FILES_METHOD = "linux-files-v1"
OLD_KEYS = (
    "destination",
    "compression",
    "compression_level",
    "network_mode",
    "schedule_time",
    "timezone",
    "keep_last",
    "volumes",
)


def _schedule(value):
    if value is None:
        return {"kind": "none"}
    if not isinstance(value, str):
        value = value.strftime("%H:%M")
    return {"kind": "daily", "time": value}


def forward(apps, schema_editor):
    Agent = apps.get_model("agents", "Agent")
    BackupPolicy = apps.get_model("imaging", "BackupPolicy")
    DeviceBackupState = apps.get_model("imaging", "DeviceBackupState")
    Image = apps.get_model("imaging", "Image")
    ImageBlock = apps.get_model("imaging", "ImageBlock")
    NativeInventory = apps.get_model("imaging", "NativeInventory")
    Profile = apps.get_model("imaging", "Profile")
    StorageTarget = apps.get_model("imaging", "StorageTarget")
    now = timezone.now()

    names = {DEFAULT_TARGET}
    for model in (Profile, Image, ImageBlock):
        names.update(model.objects.values_list("destination", flat=True).distinct())
    policies = list(BackupPolicy.objects.all())
    names.update(p.config["destination"] for p in policies if "destination" in p.config)
    targets = {
        name: StorageTarget.objects.create(
            kind="server", scope="global", name=name, is_default=name == DEFAULT_TARGET
        ).pk
        for name in sorted(names)
    }

    for policy in policies:
        config = {}
        for key, value in policy.config.items():
            if key == "destination":
                config["target"] = targets[value]
            elif key == "schedule_time":
                config["schedule"] = _schedule(value)
            else:
                config[key] = value
        policy.config = config
        policy.save(update_fields=["config"])

    methods = dict(NativeInventory.objects.values_list("agent_id", "capability"))

    def level(agent_id):
        return 1 if (methods.get(agent_id) or {}).get("method") == FILES_METHOD else 6

    by_pk = {p.pk: p.config for p in policies}
    for profile in Profile.objects.all():
        columns = {
            "target": targets[profile.destination],
            "network_mode": profile.network_mode,
            "compression": profile.compression,
            "compression_level": profile.compression_level,
            "schedule": _schedule(profile.schedule_time),
            "timezone": profile.timezone,
            "keep_last": profile.keep_last,
            "volumes": profile.volumes,
        }
        if profile.policy_id is None:
            overrides = columns
        else:
            base = {
                "target": targets[DEFAULT_TARGET],
                "network_mode": "internet",
                "compression": "gzip",
                "compression_level": level(profile.agent_id),
                "schedule": {"kind": "none"},
                "timezone": "",
                "keep_last": 0,
                "volumes": [],
                **by_pk[profile.policy_id],
            }
            overrides = {k: v for k, v in columns.items() if base.get(k) != v}
        profile.target_id = columns["target"]
        profile.overrides = overrides
        profile.effective = {
            "schedule": columns["schedule"],
            "timezone": profile.timezone,
            "min_spacing_minutes": 60,
        }
        profile.save(update_fields=["target", "overrides", "effective"])

    Profile.objects.bulk_create(
        Profile(
            agent_id=pk,
            overrides={},
            effective={},
            target_id=targets[DEFAULT_TARGET],
            destination=DEFAULT_TARGET,
            network_mode="internet",
            compression="gzip",
            compression_level=level(pk),
            schedule_time=None,
            timezone="UTC",
            next_run=None,
            keep_last=0,
            volumes=[],
        )
        for pk in Agent.objects.filter(profile__isnull=True).values_list(
            "pk", flat=True
        )
    )

    verified = dict(
        Image.objects.filter(status="verified", agent__isnull=False)
        .values("agent_id")
        .annotate(last=Max("verified_at"))
        .values_list("agent_id", "last")
    )
    scheduled = set(
        Profile.objects.filter(schedule_time__isnull=False).values_list(
            "agent_id", flat=True
        )
    )
    DeviceBackupState.objects.bulk_create(
        DeviceBackupState(
            agent_id=pk,
            last_success_at=verified.get(pk),
            schedule_since=now if pk in scheduled else None,
        )
        for pk in Agent.objects.values_list("pk", flat=True)
    )

    for name, pk in targets.items():
        Image.objects.filter(destination=name).update(target_id=pk)
    Image.objects.update(
        snapshot_at=F("created_at"),
        client_id=Subquery(
            Agent.objects.filter(pk=OuterRef("agent_id")).values("site__client_id")
        ),
    )


def backward(apps, schema_editor):
    BackupPolicy = apps.get_model("imaging", "BackupPolicy")
    DeviceBackupState = apps.get_model("imaging", "DeviceBackupState")
    Image = apps.get_model("imaging", "Image")
    PolicyChangeHold = apps.get_model("imaging", "PolicyChangeHold")
    Profile = apps.get_model("imaging", "Profile")
    StorageTarget = apps.get_model("imaging", "StorageTarget")
    Transfer = apps.get_model("imaging", "Transfer")

    BackupRun = apps.get_model("imaging", "BackupRun")
    db = schema_editor.connection.alias
    DeviceBackupState.objects.all()._raw_delete(db)
    PolicyChangeHold.objects.all()._raw_delete(db)
    # raw deletes: only assigned policies are referenced by profiles
    scoped = list(
        BackupPolicy.objects.exclude(scope="assigned").values_list("pk", flat=True)
    )
    Transfer.objects.filter(policy_id__in=scoped).update(policy=None)
    BackupRun.objects.filter(policy_id__in=scoped).update(policy=None)
    BackupPolicy.objects.filter(pk__in=scoped)._raw_delete(db)
    Transfer.objects.filter(user=None)._raw_delete(db)
    Profile.objects.filter(
        policy=None, overrides={}, schedule_time=None, keep_last=0, volumes=[]
    ).delete()
    names = dict(StorageTarget.objects.values_list("pk", "name"))
    for policy in BackupPolicy.objects.all():
        config = {}
        for key, value in policy.config.items():
            if key == "target":
                config["destination"] = names.get(value, DEFAULT_TARGET)
            elif key == "schedule":
                config["schedule_time"] = (
                    value["time"] if value.get("kind") == "daily" else None
                )
            elif key in OLD_KEYS:
                config[key] = value
        policy.config = config
        policy.save(update_fields=["config"])
    Profile.objects.update(target=None)
    Image.objects.update(target=None)
    StorageTarget.objects.all()._raw_delete(db)


class Migration(migrations.Migration):

    dependencies = [("imaging", "0006_backup_engine_schema")]

    operations = [migrations.RunPython(forward, backward)]
