# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from importlib import import_module

from django.apps import apps
from django.db import IntegrityError, connection, transaction
from model_bakery import baker

from agents.models import AgentCustomField
from ulrmm.constants import CustomFieldModel, CustomFieldType
from ulrmm.helpers import save_or_update_existing
from ulrmm.test import ULRMMTestCase

from .models import ClientCustomField, SiteCustomField
from .serializers import SiteCustomFieldSerializer

MIGRATION = (
    "clients.migrations.0002_clientcustomfield_unique_client_custom_field_and_more"
)


def drop_constraint(model, name):
    constraint = next(c for c in model._meta.constraints if c.name == name)
    with connection.schema_editor() as editor:
        editor.remove_constraint(model, constraint)


class TestOneValuePerCustomField(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()

    def text_field(self, model):
        return baker.make("core.CustomField", model=model, type=CustomFieldType.TEXT)

    def test_client_value_is_updated_not_duplicated(self):
        client = baker.make("clients.Client")
        field = self.text_field(CustomFieldModel.CLIENT)
        for value in ("one", "two"):
            payload = {
                "client": {"name": client.name},
                "custom_fields": [{"field": field.pk, "string_value": value}],
            }
            r = self.client.put(f"/clients/{client.pk}/", payload, format="json")
            self.assertEqual(r.status_code, 200)

        rows = ClientCustomField.objects.filter(client=client, field=field)
        self.assertEqual([row.string_value for row in rows], ["two"])

    def test_site_value_is_updated_not_duplicated(self):
        site = baker.make("clients.Site")
        field = self.text_field(CustomFieldModel.SITE)
        for value in ("one", "two"):
            payload = {
                "site": {"client": site.client.pk, "name": site.name},
                "custom_fields": [{"field": field.pk, "string_value": value}],
            }
            r = self.client.put(f"/clients/sites/{site.pk}/", payload, format="json")
            self.assertEqual(r.status_code, 200)

        rows = SiteCustomField.objects.filter(site=site, field=field)
        self.assertEqual([row.string_value for row in rows], ["two"])

    def test_collector_writes_one_row_per_owner(self):
        agent = baker.make_recipe("agents.agent")
        for model, owner, rows in (
            (CustomFieldModel.AGENT, agent, AgentCustomField.objects),
            (CustomFieldModel.CLIENT, agent.client, ClientCustomField.objects),
            (CustomFieldModel.SITE, agent.site, SiteCustomField.objects),
        ):
            field = self.text_field(model)
            for value in ("one", "two"):
                field.get_or_create_field_value(owner).save_to_field(value)
            self.assertEqual(
                [row.string_value for row in rows.filter(field=field)], ["two"]
            )

    def test_row_inserted_in_parallel_is_updated(self):
        site = baker.make("clients.Site")
        field = self.text_field(CustomFieldModel.SITE)
        serializer = SiteCustomFieldSerializer(
            data={"site": site.pk, "field": field.pk, "string_value": "mine"}
        )
        self.assertTrue(serializer.is_valid())
        theirs = SiteCustomField.objects.create(
            site=site, field=field, string_value="theirs"
        )

        save_or_update_existing(serializer, SiteCustomField, site=site, field=field)

        rows = SiteCustomField.objects.filter(site=site, field=field)
        self.assertEqual(
            list(rows.values_list("pk", "string_value")), [(theirs.pk, "mine")]
        )

    def test_database_refuses_a_second_value(self):
        client = baker.make("clients.Client")
        field = self.text_field(CustomFieldModel.CLIENT)
        ClientCustomField.objects.create(client=client, field=field)
        with self.assertRaises(IntegrityError), transaction.atomic():
            ClientCustomField.objects.create(client=client, field=field)


class TestCustomFieldDuplicatesMigration(ULRMMTestCase):
    def test_keeps_the_newest_row(self):
        drop_constraint(ClientCustomField, "unique_client_custom_field")
        drop_constraint(SiteCustomField, "unique_site_custom_field")
        site = baker.make("clients.Site")
        client_field = baker.make("core.CustomField", model=CustomFieldModel.CLIENT)
        site_field = baker.make("core.CustomField", model=CustomFieldModel.SITE)
        other_field = baker.make("core.CustomField", model=CustomFieldModel.SITE)
        client_rows = [
            ClientCustomField.objects.create(client=site.client, field=client_field)
            for _ in range(3)
        ]
        site_rows = [
            SiteCustomField.objects.create(site=site, field=site_field)
            for _ in range(2)
        ]
        single = SiteCustomField.objects.create(site=site, field=other_field)

        for _ in range(2):
            import_module(MIGRATION).drop_older_duplicates(apps, None)

        self.assertEqual(
            list(ClientCustomField.objects.values_list("pk", flat=True)),
            [client_rows[-1].pk],
        )
        self.assertEqual(
            sorted(SiteCustomField.objects.values_list("pk", flat=True)),
            sorted([site_rows[-1].pk, single.pk]),
        )
