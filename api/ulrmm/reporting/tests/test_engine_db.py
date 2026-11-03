# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import base64
import json
import os
import shutil
import sys
import tempfile
import uuid
from types import SimpleNamespace
from unittest.mock import Mock, patch

from django.apps import apps
from django.conf import settings
from django.test import override_settings
from jinja2.sandbox import SecurityError
from model_bakery import baker
from rest_framework.exceptions import ValidationError

from agents.models import Agent
from reporting import schema
from reporting.constants import REPORTING_MODELS, get_property_fields
from reporting.utils import InvalidDBOperationException, ResolveModelException
from reporting.utils import (
    _import_assets,
    _import_base_template,
    _import_report_template,
    add_custom_fields,
    base64_encode_assets,
    build_queryset,
    build_report_link,
    db_template_loader,
    decode_base64_asset,
    env,
    generate_html,
    import_report_bundle,
    normalize_asset_url,
    prep_variables_for_template,
    process_dependencies,
)
from reporting.utils import resolve_model, run_report, run_scheduled_report
from ulrmm.test import ULRMMTestCase


def model(name):
    return apps.get_model("reporting", name)


def query(data_source, user=None, limit=None):
    return build_queryset(
        data_source=resolve_model(data_source=data_source), limit=limit, user=user
    )


class AssetRootMixin:
    def setUp(self):
        super().setUp()
        self.asset_root = tempfile.mkdtemp()
        override = override_settings(
            REPORTING_ASSETS_BASE_PATH=self.asset_root,
            REPORTING_BASE_URL="https://api.example.com",
        )
        override.enable()
        self.addCleanup(override.disable)
        self.addCleanup(shutil.rmtree, self.asset_root, True)

    def make_asset(self, name, content=b"content"):
        path = os.path.join(self.asset_root, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(content)
        return model("ReportAsset").objects.create(file=name)


class TestRendering(ULRMMTestCase):
    def test_loader(self):
        baker.make(
            "reporting.ReportHTMLTemplate", name="test_html_template", html="Test HTML"
        )
        baker.make(
            "reporting.ReportTemplate", name="test_md_template", template_md="Test MD"
        )
        baker.make(
            "reporting.ReportHTMLTemplate", name="common_template", html="from base"
        )
        baker.make(
            "reporting.ReportTemplate", name="common_template", template_md="from md"
        )

        self.assertEqual(db_template_loader("test_html_template")[0], "Test HTML")
        self.assertEqual(db_template_loader("test_md_template")[0], "Test MD")
        self.assertEqual(db_template_loader("common_template")[0], "from base")
        self.assertIsNone(db_template_loader("missing"))

    def test_base_template(self):
        base = baker.make(
            "reporting.ReportHTMLTemplate",
            name='Base "quoted" Template',
            html="<html>{% block content %}{% endblock %}</html>",
        )
        body = "{% block content %}<h1>Heading</h1>{% endblock %}"
        html, _ = generate_html(body, "html", html_template=base.pk)
        self.assertEqual(html, "<html><h1>Heading</h1></html>")

        # edits show up without a restart
        base.html = "<main>{% block content %}{% endblock %}</main>"
        base.save()
        html, _ = generate_html(body, "html", html_template=base.pk)
        self.assertEqual(html, "<main><h1>Heading</h1></main>")

        html, _ = generate_html("<h1>alone</h1>", "html", html_template=99999)
        self.assertEqual(html, "<h1>alone</h1>")

    def test_markdown_variables_and_css(self):
        html, variables = generate_html(
            "# This is a header\n\nHello {{ name }}\n\n<style>{{ css }}</style>",
            "markdown",
            css=".my-class > p { color: red; }",
            variables="name: John\ncss: ignored",
        )
        self.assertIn("<h1>This is a header</h1>", html)
        self.assertIn("Hello John", html)
        self.assertIn(".my-class > p { color: red; }", html)
        self.assertEqual(variables["name"], "John")

    def test_author_values_raw_database_text_escaped(self):
        agent = baker.make_recipe(
            "agents.agent", hostname="host-1", description="<i>desc</i> & more"
        )
        variables = (
            "banner: '<b>Bold</b> & <i>it</i>'\n"
            "items: [a, b]\n"
            "title: 'Report {{month}} for {{agent.hostname}}'\n"
            'quoted: "{{quote}}"\n'
            "data_sources:\n"
            "  rows: {model: agent, only: [hostname, description]}\n"
            "  as_json: {model: agent, only: [description], json: true}\n"
            "  as_csv: {model: agent, only: [description], csv: true}\n"
            "  total: {model: agent, count: true}\n"
        )
        template = (
            "{{ banner }}|{{ items }}|{{ title }}|{{ quoted }}|{{ '<u>' ~ banner }}|"
            "{{ agent.description }}|{{ agent.hostname ~ '<br>' }}|"
            "{% for row in data_sources.rows %}{{ row.description }}{% endfor %}|"
            "<script>var d = {{ data_sources.as_json }};</script>|"
            "{{ data_sources.as_csv }}|{{ data_sources.total }}"
        )
        dependencies = {"agent": agent.agent_id, "month": "May", "quote": 'it\'s "q"'}
        html, _ = generate_html(
            template, "html", variables=variables, dependencies=dependencies
        )
        parts = html.split("|")
        self.assertEqual(parts[0], "<b>Bold</b> & <i>it</i>")
        self.assertEqual(parts[1], "['a', 'b']")
        self.assertEqual(parts[2], "Report May for host-1")
        self.assertEqual(parts[3], 'it\'s "q"')
        self.assertEqual(parts[4], "<u><b>Bold</b> & <i>it</i>")
        self.assertEqual(parts[5], "&lt;i&gt;desc&lt;/i&gt; &amp; more")
        self.assertEqual(parts[6], "host-1<br>")
        self.assertEqual(parts[7], "&lt;i&gt;desc&lt;/i&gt; &amp; more")
        script = parts[8][len("<script>var d = ") : -len(";</script>")]
        self.assertEqual(json.loads(script)[0]["description"], "<i>desc</i> & more")
        self.assertNotIn("<i>", script)
        self.assertEqual(parts[9], "description\n&lt;i&gt;desc&lt;/i&gt; &amp; more\n")
        self.assertEqual(parts[10], "1")

        html, _ = generate_html(
            template, "plaintext", variables=variables, dependencies=dependencies
        )
        self.assertEqual(html.split("|")[5], "<i>desc</i> & more")
        self.assertIn('"<i>desc</i> & more"', html.split("|")[8])

    def test_syntax_error_before_queries(self):
        with patch("reporting.utils.prep_variables_for_template") as prep:
            with self.assertRaises(Exception) as error:
                generate_html("{% if %}", "markdown", variables="")
        self.assertTrue(hasattr(error.exception, "lineno"))
        prep.assert_not_called()

    def test_prep_order(self):
        with patch(
            "reporting.utils.process_dependencies", return_value={"a": 1}
        ) as deps, patch(
            "reporting.utils.process_data_sources", return_value={"b": 2}
        ) as sources, patch(
            "reporting.utils.process_chart_variables", return_value={"c": 3}
        ) as charts:
            self.assertEqual(prep_variables_for_template("x: 1", {}, 1), {"c": 3})
        self.assertEqual(sources.call_args.kwargs["variables"], {"a": 1})
        self.assertEqual(sources.call_args.kwargs["limit_query_results"], 1)
        self.assertEqual(charts.call_args.kwargs["variables"], {"b": 2})
        deps.assert_called_once()
        self.assertEqual(prep_variables_for_template(""), {})


class TestSandbox(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.agent = baker.make_recipe("agents.online_agent", hostname="host1")

    @patch("agents.models.Agent.nats_cmd")
    def test_reads_but_never_runs(self, nats_cmd):
        html, _ = generate_html(
            "{{ agent.hostname }}|{{ agent.site.name }}|{{ agent.client.name }}|{{ agent.status }}",
            "html",
            dependencies={"agent": self.agent.agent_id},
        )
        self.assertEqual(
            html,
            f"host1|{self.agent.site.name}|{self.agent.site.client.name}|online",
        )

        script = baker.make("scripts.Script")
        for source in (
            "{{ agent.run_script(" + str(script.pk) + ") }}",
            "{{ (agent|attr('recover'))('mesh') }}",
            "{{ agent.site.agents.all() }}",
            "{{ agent.site.agents.create(hostname='x') }}",
            "{{ agent._meta.app_label }}",
        ):
            with self.subTest(source=source), self.assertRaises(SecurityError):
                generate_html(
                    source, "html", dependencies={"agent": self.agent.agent_id}
                )
        nats_cmd.assert_not_called()
        self.assertEqual(Agent.objects.count(), 1)

    def test_credentials_stay_hidden(self):
        user = baker.make("accounts.User", username="owner", agent=self.agent)
        user.set_password("hunter2")
        user.save()
        token = baker.make("authtoken.Token", user=user)

        with self.assertRaises(SecurityError):
            generate_html(
                "{{ agent.user.auth_token.key }}",
                "html",
                dependencies={"agent": self.agent.agent_id},
            )
        html, _ = generate_html(
            "{{ agent.user.password }}|{{ agent.user.username }}",
            "html",
            dependencies={"agent": self.agent.agent_id},
        )
        self.assertEqual(html, "|")

        variables = process_dependencies(
            'token: "{{agent.user.auth_token.key}}"\npassword: "{{agent.user.password}}"\n'
            'secret: "{{agent._meta.SECRET_KEY}}"\nhost: "{{agent.hostname}}"',
            {"agent": self.agent.agent_id},
        )
        dumped = json.dumps(variables, default=str)
        self.assertEqual(variables["token"], "{{agent.user.auth_token.key}}")
        self.assertEqual(variables["password"], "{{agent.user.password}}")
        self.assertEqual(variables["secret"], "{{agent._meta.SECRET_KEY}}")
        self.assertEqual(variables["host"], "host1")
        for secret in (token.key, user.password, settings.SECRET_KEY):
            self.assertNotIn(secret, dumped)

    def test_vault_credential_is_unsafe(self):
        credential = apps.get_model("vault", "Credential")(name="cred")
        self.assertFalse(env.is_safe_attribute(credential, "name", credential.name))


class TestDependencies(ULRMMTestCase):
    def setUp(self):
        self.client1 = baker.make("clients.Client", name="Client One")
        self.client2 = baker.make("clients.Client", name="Client Two")
        self.site1 = baker.make("clients.Site", client=self.client1, name="Site One")
        self.site2 = baker.make("clients.Site", client=self.client2, name="Site Two")
        self.agent1 = baker.make_recipe(
            "agents.agent", site=self.site1, hostname="agent1"
        )
        self.agent2 = baker.make_recipe(
            "agents.agent", site=self.site2, hostname="agent2"
        )

    def test_model_and_value_placeholders(self):
        baker.make("core.GlobalKVStore", name="some_global_value", value="global value")
        dependencies = {
            "client": self.client1.pk,
            "site": self.site1.pk,
            "agent": self.agent1.agent_id,
            "dep_1": "first",
            "dep_2": "second",
        }
        variables = process_dependencies(
            "c: {{client.name}}\ns: {{site.name}}\na: {{agent.hostname}}\n"
            "d1: {{dep_1}}\nd2: '{{ dep_2 }}'\ng: {{global.some_global_value}}\n"
            'missing: "{{missing_dependency}}"\nnested:\n  client_field: {{client.name}}',
            dependencies,
        )
        self.assertEqual(variables["c"], "Client One")
        self.assertEqual(variables["s"], "Site One")
        self.assertEqual(variables["a"], "agent1")
        self.assertEqual((variables["d1"], variables["d2"]), ("first", "second"))
        self.assertEqual(variables["g"], "global value")
        self.assertEqual(variables["missing"], "{{missing_dependency}}")
        self.assertEqual(variables["nested"]["client_field"], "Client One")
        self.assertIsInstance(variables["agent"], Agent)
        self.assertEqual(variables["client"], self.client1)
        self.assertEqual(variables["dep_1"], "first")
        # the caller's mapping is not changed
        self.assertEqual(dependencies["agent"], self.agent1.agent_id)

    def test_injection_through_values(self):
        self.agent1.hostname = "evil\ndata_sources:\n  all: {model: agent}"
        self.agent1.save()
        variables = process_dependencies(
            "name: {{agent.hostname}}", {"agent": self.agent1.agent_id}
        )
        self.assertNotIn("data_sources", variables)
        self.assertEqual(variables["name"], self.agent1.hostname)

    def test_role_scope_and_missing_objects(self):
        user = self.create_user_with_roles(["can_view_reports"])
        user.role.can_view_clients.set([self.client1])

        process_dependencies("", {"agent": self.agent1.agent_id}, user)
        for dependencies in (
            {"agent": self.agent2.agent_id},
            {"client": self.client2.pk},
            {"site": self.site2.pk},
        ):
            with self.subTest(dependencies=dependencies), self.assertRaises(
                Exception
            ) as error:
                process_dependencies("", dependencies, user)
            self.assertIn("does not exist", str(error.exception))

        with self.assertRaises(Agent.DoesNotExist):
            process_dependencies("", {"agent": "nope"})
        for reserved in ("data_sources", "charts"):
            with self.assertRaises(ValueError):
                process_dependencies("", {reserved: {"model": "agent"}})


class TestQueries(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.agent1 = baker.make_recipe(
            "agents.online_agent", hostname="ZAgent1", operating_system="Windows 11"
        )
        self.agent2 = baker.make_recipe(
            "agents.agent", hostname="Agent2", operating_system="Windows 10"
        )

    def test_models_resolve(self):
        for name, app in REPORTING_MODELS:
            self.assertEqual(
                resolve_model({"model": name.upper()})["model"],
                apps.get_model(app, name),
            )
        with self.assertRaisesMessage(
            ResolveModelException, "Model lookup failed for InvalidModel"
        ):
            resolve_model({"model": "InvalidModel"})
        for data_source in ({}, {"only": ["x"]}):
            with self.assertRaisesMessage(
                ResolveModelException, "Model key must be present on data_source"
            ):
                resolve_model(data_source)
        with self.assertRaises(ResolveModelException):
            build_queryset(data_source={"model": apps.get_model("accounts", "User")})

    def test_operations(self):
        self.assertEqual(len(query({"model": "agent"})), 2)
        for key in ("invalid_op", "meta", "raw", "update", "delete"):
            with self.subTest(key=key), self.assertRaises(InvalidDBOperationException):
                query({"model": "agent", key: True})
        for key in ("annotate", "aggregate"):
            with self.assertRaisesMessage(InvalidDBOperationException, "not supported"):
                query({"model": "agent", key: {"x": "y"}})

        rows = query({"model": "agent", "only": ["hostname", "operating_system"]})
        self.assertEqual(len(rows), 2)
        self.assertEqual(set(rows[0]), {"hostname", "operating_system", "id"})

        rows = query(
            {
                "model": "agent",
                "filter": {"hostname": "ZAgent1"},
                "only": ["agent_id", "hostname"],
            }
        )
        self.assertEqual(len(rows), 1)
        self.assertNotIn("plat", rows[0])
        self.assertEqual(query({"model": "agent", "filter": {"hostname": "none"}}), [])
        self.assertEqual(
            query({"model": "agent", "exclude": {"hostname": "ZAgent1"}})[0][
                "hostname"
            ],
            "Agent2",
        )
        self.assertEqual(
            query({"model": "agent", "get": {"agent_id": self.agent1.agent_id}})[
                "hostname"
            ],
            "ZAgent1",
        )
        self.assertEqual(
            query({"model": "agent", "first": True})["hostname"], "ZAgent1"
        )
        self.assertEqual(query({"model": "agent", "count": True}), 2)
        self.assertEqual(len(query({"model": "agent", "all": True})), 2)
        self.assertEqual(len(query({"model": "agent", "limit": 1})), 1)
        self.assertIsInstance(
            query({"model": "agent", "limit": 1, "first": True}), dict
        )
        self.assertIsInstance(
            query({"model": "agent", "limit": 5, "get": {"hostname": "Agent2"}}), dict
        )
        self.assertEqual(
            [
                r["hostname"]
                for r in query(
                    {
                        "model": "agent",
                        "filter": {"plat": "windows"},
                        "order_by": ["hostname"],
                    }
                )
            ],
            ["Agent2", "ZAgent1"],
        )

        rows = query({"model": "agent", "defer": ["wmi_detail", "services"]})
        self.assertNotIn("wmi_detail", rows[0])
        self.assertIn("hostname", rows[0])
        rows = query(
            {
                "model": "agent",
                "only": ["hostname", "operating_system"],
                "defer": ["operating_system"],
            }
        )
        self.assertEqual(set(rows[0]), {"hostname", "id"})

    def test_output_formats(self):
        data = json.loads(
            query({"model": "agent", "order_by": ["-hostname"], "json": True})
        )
        self.assertIsInstance(data, list)
        self.assertEqual(data[0]["hostname"], "ZAgent1")
        data = json.loads(
            query(
                {
                    "model": "agent",
                    "get": {"hostname": "Agent2"},
                    "only": ["hostname"],
                    "json": True,
                }
            )
        )
        self.assertEqual(data["hostname"], "Agent2")
        self.assertNotIn("operating_system", data)

        text = query(
            {"model": "agent", "only": ["hostname", "operating_system"], "csv": True}
        )
        header = text.splitlines()[0]
        self.assertEqual(header, "hostname,operating_system")
        text = query(
            {
                "model": "agent",
                "only": ["hostname", "operating_system"],
                "csv": {"hostname": "Hostname", "operating_system": "Operating System"},
            }
        )
        self.assertEqual(text.splitlines()[0], "Hostname,Operating System")

    def test_explicit_false_flags(self):
        for flag in ("count", "first", "get", "all", "json", "csv"):
            with self.subTest(flag=flag):
                result = query({"model": "agent", flag: False})
                self.assertIsInstance(result, list)
                self.assertEqual(len(result), 2)

    def test_related_paths_and_datetimes(self):
        row = query(
            {
                "model": "agent",
                "only": ["hostname", "site__name", "site__client__name"],
                "first": True,
            }
        )
        self.assertEqual(row["site__name"], self.agent1.site.name)
        self.assertIn("site__client__name", row)
        query(
            {
                "model": "agent",
                "select_related": ["site", "site__client"],
                "first": True,
            }
        )
        row = query(
            {
                "model": "agent",
                "only": ["site__name", "hostname"],
                "select_related": ["site", "site__client"],
                "first": True,
            }
        )
        self.assertNotIn("site__client", row)

        row = query(
            {
                "model": "agent",
                "only": ["hostname", "last_seen", "created_time"]
                + ["site__created_time", "site__client__created_time"],
                "first": True,
            }
        )
        import datetime

        for key in ("last_seen", "site__created_time", "site__client__created_time"):
            self.assertIsInstance(row[key], datetime.datetime)

    def test_properties(self):
        rows = query(
            {"model": "agent", "properties": ["status", "checks", "invalid", "save"]}
        )
        for row in rows:
            self.assertIn("status", row)
            self.assertIn("checks", row)
            self.assertNotIn("invalid", row)
            self.assertNotIn("save", row)

        rows = query(
            {
                "model": "agent",
                "only": ["hostname", "plat"],
                "defer": ["plat"],
                "properties": ["status"],
            }
        )
        self.assertEqual(set(rows[0]), {"hostname", "id", "status"})

        row = query(
            {"model": "agent", "first": True, "properties": ["status", "checks"]}
        )
        self.assertEqual(row["status"], self.agent1.status)
        self.assertIsNotNone(row["checks"])
        self.assertIn("status", get_property_fields(Agent))
        self.assertNotIn("pk", get_property_fields(Agent))

    def test_custom_fields(self):
        field1 = baker.make(
            "core.CustomField", model="agent", type="text", name="custom1"
        )
        baker.make(
            "core.CustomField",
            model="agent",
            type="text",
            name="custom2",
            default_value_string="Default",
        )
        baker.make(
            "agents.AgentCustomField",
            agent=self.agent1,
            field=field1,
            string_value="one",
        )
        baker.make(
            "agents.AgentCustomField",
            agent=self.agent2,
            field=field1,
            string_value="two",
        )

        rows = query(
            {
                "model": "agent",
                "only": ["hostname"],
                "custom_fields": ["custom1", "custom2", "unknown"],
            }
        )
        values = {row["hostname"]: row["custom_fields"] for row in rows}
        self.assertEqual(values["ZAgent1"], {"custom1": "one", "custom2": "Default"})
        self.assertEqual(values["Agent2"], {"custom1": "two", "custom2": "Default"})

        row = query({"model": "agent", "first": True, "custom_fields": ["custom1"]})
        self.assertEqual(row["custom_fields"], {"custom1": "one"})
        query({"model": "alert", "custom_fields": ["custom1"]})

        for model_name in ("client", "site"):
            field = baker.make(
                "core.CustomField",
                default_value_string="default_value",
                model=model_name,
                type="text",
                name="field1",
            )
            obj = self.agent1.site if model_name == "site" else self.agent1.site.client
            baker.make(
                f"clients.{model_name.capitalize()}CustomField",
                **{model_name: obj, "field": field, "string_value": "Value"},
            )
            self.assertEqual(
                add_custom_fields([{"id": obj.id}], ["field1"], model_name)[0][
                    "custom_fields"
                ],
                {"field1": "Value"},
            )
            self.assertEqual(
                add_custom_fields({"id": 999}, ["field1"], model_name)["custom_fields"],
                {"field1": "default_value"},
            )

    def test_credential_guard(self):
        device = baker.make(
            "netmon.NetworkDevice", site=self.agent1.site, snmp_secret="s3cret"
        )
        for data_source in (
            {"model": "Site", "only": ["network_devices__snmp_secret"]},
            {"model": "Client", "values": ["sites__network_devices__host"]},
            {"model": "Alert", "only": ["network_device__snmp_secret"]},
            {
                "model": "Alert",
                "filter": {"network_device__snmp_secret__startswith": "s"},
            },
            {"model": "Alert", "order_by": ["-network_device__pk"]},
            {"model": "Agent", "only": ["rustdesk_peer__password"]},
            {"model": "Agent", "select_related": "rustdesk_peer__agent"},
            {"model": "Note", "values": ["user__password"]},
            {"model": "Client", "values": ["vault_documents__body"]},
            {"model": "Agent", "filter": {"vault_documents__title__startswith": "a"}},
            {"model": "Agent", "only": ["vault_credentials__secret"]},
            {"model": "Site", "values": ["vault_credentials__name"]},
            {
                "model": "Client",
                "filter": {"vault_credentials__secret__startswith": "g"},
            },
            {"model": "Alert", "get": {"network_device__name": "x"}},
            {"model": "Alert", "csv": {"network_device__name": "Name"}},
        ):
            with self.subTest(data_source=data_source), self.assertRaises(
                InvalidDBOperationException
            ):
                query(data_source)

        baker.make("alerts.Alert", network_device=device, message="device alert")
        baker.make("alerts.Alert", agent=self.agent1, message="agent alert")
        rows = query(
            {
                "model": "Alert",
                "only": ["network_device", "message"],
                "filter": {"network_device__isnull": False},
            }
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["network_device"], device.pk)

    def test_role_scope(self):
        user = self.create_user_with_roles(["can_view_reports"])
        user.role.can_view_clients.set([self.agent1.site.client])
        self.assertLess(
            len(query({"model": "agent"}, user)), len(query({"model": "agent"}))
        )
        self.assertEqual(len(query({"model": "agent"}, user)), 1)

        baker.make("winupdate.WinUpdate", agent=self.agent1, kb="KB1")
        baker.make("winupdate.WinUpdate", agent=self.agent2, kb="KB2")
        self.assertEqual(
            [r["kb"] for r in query({"model": "winupdate"}, user)], ["KB1"]
        )

        field = baker.make("core.CustomField", model="site", type="text", name="f")
        baker.make("clients.SiteCustomField", site=self.agent1.site, field=field)
        baker.make("clients.SiteCustomField", site=self.agent2.site, field=field)
        self.assertEqual(len(query({"model": "sitecustomfield"}, user)), 1)

        for name in ("globalkvstore", "auditlog", "debuglog"):
            with self.subTest(name=name), self.assertRaisesMessage(
                InvalidDBOperationException, "superusers"
            ):
                query({"model": name}, user)
        superuser = self.create_user_with_roles(["is_superuser"])
        query({"model": "globalkvstore"}, superuser)
        self.assertEqual(len(query({"model": "agent"}, superuser)), 2)

        no_role = baker.make("accounts.User")
        self.assertEqual(query({"model": "agent"}, no_role), [])

        with patch(
            "ulrmm.models.PermissionQuerySet.filter_by_role",
            side_effect=RuntimeError("boom"),
        ):
            with self.assertRaises(InvalidDBOperationException):
                query({"model": "agent"}, user)
            with self.assertRaises(InvalidDBOperationException):
                query({"model": "winupdate"}, user)

    def test_unrestricted_role_sees_every_row(self):
        # a role without client and site limits, like filter_by_role
        user = self.create_user_with_roles(["can_manage_reports"])
        policy = baker.make("automation.Policy", name="p")
        baker.make("winupdate.WinUpdatePolicy", agent=self.agent1)
        policy_row = baker.make("winupdate.WinUpdatePolicy", agent=None, policy=policy)
        everything = query({"model": "winupdatepolicy", "count": True})
        self.assertEqual(
            query({"model": "winupdatepolicy", "count": True}, user), everything
        )
        self.assertEqual(len(query({"model": "agent"}, user)), 2)
        rows = query({"model": "site", "values": ["agents__hostname"]}, user)
        self.assertEqual(len(rows), 2)
        with self.assertRaisesMessage(InvalidDBOperationException, "superusers"):
            query({"model": "debuglog"}, user)

        user.role.can_view_clients.set([self.agent1.site.client])
        rows = query({"model": "winupdatepolicy", "values": ["agent"]}, user)
        self.assertNotIn(policy_row.pk, [row["id"] for row in rows])
        self.assertEqual({row["agent"] for row in rows}, {self.agent1.pk})
        with self.assertRaises(InvalidDBOperationException):
            query({"model": "site", "values": ["agents__hostname"]}, user)

    def test_row_cap(self):
        with override_settings(REPORTING_MAX_ROWS=1):
            self.assertEqual(len(query({"model": "agent"})), 1)
            self.assertEqual(len(query({"model": "agent", "limit": 50})), 1)
            self.assertEqual(query({"model": "agent", "count": True}), 2)
        self.assertEqual(len(query({"model": "agent", "limit": 50}, limit=1)), 1)
        for bad in (-1, "5", 1.5):
            with self.assertRaises(InvalidDBOperationException):
                query({"model": "agent", "limit": bad})
        for no_limit in (0, None, False):
            self.assertEqual(len(query({"model": "agent", "limit": no_limit})), 2)
        self.assertEqual(len(query({"model": "agent", "limit": True})), 1)

    def test_variables_with_data_sources(self):
        _, variables = generate_html(
            "{{ data_sources.agent.last_seen.astimezone(ZoneInfo('America/Los_Angeles')).strftime('%Y') }}",
            "html",
            variables="data_sources:\n  agent:\n    model: agent\n    only: [last_seen]\n    first: true\n  named: some_query",
        )
        self.assertEqual(variables["data_sources"]["named"], "some_query")
        self.assertIn("last_seen", variables["data_sources"]["agent"])


class TestAssets(AssetRootMixin, ULRMMTestCase):
    def test_encode_and_normalize(self):
        first = self.make_asset("img/a b.png", b"first")
        second = self.make_asset("second.png", b"second")
        unknown = uuid.uuid4()
        text = f"asset://{second.id} asset://{first.id} asset://{second.id} asset://{unknown}"

        encoded = base64_encode_assets(text)
        self.assertEqual([e["id"] for e in encoded], [str(second.id), str(first.id)])
        self.assertEqual(base64.b64decode(encoded[1]["file"]), b"first")
        self.assertEqual(encoded[1]["name"], "img/a b.png")
        self.assertEqual(base64_encode_assets("no assets"), [])

        html = normalize_asset_url(text, "html")
        self.assertIn(
            f"https://api.example.com/reporting/assets/img/a%20b.png?id={first.id}",
            html,
        )
        self.assertIn(f"asset://{unknown}", html)
        self.assertEqual(html.count("asset://"), 1)
        for format in ("pdf", "plaintext"):
            normalized = normalize_asset_url(f"asset://{second.id}", format)
            self.assertEqual(
                normalized, f"file://{os.path.join(self.asset_root, 'second.png')}"
            )
        self.assertEqual(normalize_asset_url("plain text", "html"), "plain text")

        self.assertEqual(
            decode_base64_asset(base64.b64encode(b"Hello, world!").decode()),
            b"Hello, world!",
        )
        with self.assertRaises(Exception):
            decode_base64_asset("Not a base64 encoded string.")

    def test_import_assets(self):
        self.make_asset("img/logo.png", b"existing")
        new_id = str(uuid.uuid4())
        written = []
        id_map = _import_assets(
            [
                {
                    "id": new_id,
                    "name": "img/logo.png",
                    "file": base64.b64encode(b"new").decode(),
                },
                {
                    "id": str(uuid.uuid4()),
                    "name": "other.png",
                    "file": base64.b64encode(b"other").decode(),
                },
            ],
            written,
        )
        self.assertEqual(id_map[new_id], new_id)
        stored = model("ReportAsset").objects.get(id=new_id).file.name
        self.assertTrue(stored.startswith("img/logo_"))
        with open(os.path.join(self.asset_root, stored), "rb") as f:
            self.assertEqual(f.read(), b"new")
        self.assertEqual(len(written), 2)

        # an existing id never gets a different file
        existing = model("ReportAsset").objects.get(file="img/logo.png")
        same = _import_assets(
            [
                {
                    "id": str(existing.id),
                    "name": "x.png",
                    "file": base64.b64encode(b"existing").decode(),
                }
            ]
        )
        self.assertEqual(same[str(existing.id)], str(existing.id))
        other = _import_assets(
            [
                {
                    "id": str(existing.id),
                    "name": "x.png",
                    "file": base64.b64encode(b"changed").decode(),
                }
            ]
        )
        self.assertNotEqual(other[str(existing.id)], str(existing.id))
        existing.refresh_from_db()
        self.assertEqual(existing.file.name, "img/logo.png")

        for entry in (
            {"id": "bad", "name": "a.png", "file": ""},
            {"id": new_id, "name": "a.html", "file": ""},
            {"id": new_id, "name": "../a.png", "file": ""},
            {"id": new_id, "name": "a.png"},
        ):
            with self.subTest(entry=entry), self.assertRaises(Exception):
                _import_assets([entry])
        with override_settings(REPORTING_MAX_ASSET_MB=0):
            with self.assertRaises(ValidationError):
                _import_assets(
                    [
                        {
                            "id": str(uuid.uuid4()),
                            "name": "big.png",
                            "file": base64.b64encode(b"xx").decode(),
                        }
                    ]
                )
        self.assertEqual(_import_assets("not a list"), {})


class TestImport(AssetRootMixin, ULRMMTestCase):
    def test_base_template(self):
        first = _import_base_template({"name": "base", "html": "<div></div>"})
        self.assertEqual(model("ReportHTMLTemplate").objects.get(pk=first).name, "base")
        second = _import_base_template({"name": "base", "html": "<p></p>"})
        self.assertRegex(
            model("ReportHTMLTemplate").objects.get(pk=second).name, r"^base_[a-z]{6}$"
        )
        self.assertEqual(
            _import_base_template({"name": "base", "html": "<b></b>"}, overwrite=True),
            first,
        )
        self.assertEqual(
            model("ReportHTMLTemplate").objects.get(pk=first).html, "<b></b>"
        )
        self.assertIsNone(_import_base_template(None))
        with self.assertRaisesMessage(ValidationError, "missing 'name' key"):
            _import_base_template({"html": "x"})
        with self.assertRaisesMessage(ValidationError, "missing 'html' field"):
            _import_base_template({"name": "x"})

    def test_report_template(self):
        base = _import_base_template({"name": "base", "html": "x"})
        data = {
            "name": "t" * 200,
            "template_md": "# x",
            "type": "markdown",
            "depends_on": ["agent"],
        }
        created = _import_report_template(data, base)
        self.assertEqual(created.template_html_id, base)
        copy = _import_report_template(data, base)
        self.assertEqual(len(copy.name), 200)
        self.assertNotEqual(copy.name, created.name)

        updated = _import_report_template(
            {
                **data,
                "template_md": "# new",
                "id": 999,
                "created_by": "mallory",
                "modified_time": None,
            },
            None,
            overwrite=True,
        )
        self.assertEqual(updated.pk, created.pk)
        self.assertEqual(updated.template_md, "# new")
        self.assertIsNone(updated.template_html_id)
        self.assertNotEqual(updated.created_by, "mallory")

        for bad, message in (
            ({}, "'template' key is required"),
            ({"template_md": "x"}, "'name' key"),
            ({"name": "x"}, "'template_md' field"),
            ({"name": "x", "template_md": "x", "type": "exe"}, "type must be"),
            (
                {"name": "x", "template_md": "x", "depends_on": ["site", "charts"]},
                "charts cannot be used as a dependency name",
            ),
        ):
            with self.assertRaisesMessage(ValidationError, message):
                _import_report_template(bad)

    def test_bundle(self):
        existing = self.make_asset("logo.png", b"old")
        bundle = {
            "base_template": {
                "name": "base",
                "html": f"<img src='asset://{existing.id}'>",
            },
            "template": {
                "name": "report",
                "template_md": f"![](asset://{existing.id})",
                "type": "markdown",
            },
            "assets": [
                {
                    "id": str(existing.id),
                    "name": "logo.png",
                    "file": base64.b64encode(b"new").decode(),
                }
            ],
        }
        template = import_report_bundle(bundle)
        new_id = template.template_md.split("asset://")[1].rstrip(")")
        self.assertNotEqual(new_id, str(existing.id))
        self.assertIn(new_id, template.template_html.html)
        self.assertTrue(model("ReportAsset").objects.filter(id=new_id).exists())

        failing = {
            "template": {"name": "broken"},
            "assets": [
                {
                    "id": str(uuid.uuid4()),
                    "name": "fresh.png",
                    "file": base64.b64encode(b"x").decode(),
                }
            ],
        }
        files_before = sorted(os.listdir(self.asset_root))
        with self.assertRaises(ValidationError):
            import_report_bundle(failing)
        self.assertEqual(sorted(os.listdir(self.asset_root)), files_before)
        self.assertFalse(model("ReportTemplate").objects.filter(name="broken").exists())


class TestRuns(AssetRootMixin, ULRMMTestCase):
    def setUp(self):
        super().setUp()
        self.template = baker.make(
            "reporting.ReportTemplate",
            name="report",
            template_md="# Report {{ name }}",
            type="markdown",
            template_variables="name: test",
        )

    def test_run_html_and_pdf(self):
        user = baker.make("accounts.User", username="runner")
        output, error, history = run_report(self.template, {}, "html", user)
        self.assertIsNone(error)
        self.assertIn("<h1>Report test</h1>", output)
        self.assertEqual(history.report_data, output)
        self.assertIsNone(history.error_data)
        self.assertEqual(history.run_by, "runner")

        output, error, history = run_report(self.template, {}, "pdf")
        self.assertTrue(output.startswith(b"%PDF"))
        self.assertEqual(history.run_by, "system")

        with patch("reporting.utils.generate_pdf", side_effect=OSError("/secret/path")):
            output, error, history = run_report(self.template, {}, "pdf")
        self.assertIsNone(output)
        self.assertNotIn("/secret/path", error)
        self.assertEqual(model("ReportHistory").objects.count(), 3)

    def test_run_errors(self):
        for template_md, variables, expected in (
            ("{% if %}", "", "Line 1:"),
            (
                "x",
                "data_sources:\n  a: {model: agent, bad_op: 1}",
                "bad_op not allowed",
            ),
            (
                "{{ data_sources.a }}",
                "data_sources:\n  a: {model: nothing}",
                "Model lookup failed",
            ),
            ("x", "a: [", ""),
        ):
            self.template.template_md = template_md
            self.template.template_variables = variables
            self.template.save()
            with self.subTest(template_md=template_md):
                output, error, history = run_report(self.template, {}, "html")
                self.assertIsNone(output)
                self.assertIn(expected, error)
                self.assertEqual(history.report_data, "")
                self.assertEqual(history.error_data, error)

        output, error, _ = run_report(self.template, {"agent": "missing"}, "html")
        self.assertIn("does not exist", error)
        _, error, _ = run_report(self.template, {}, "docx")
        self.assertEqual(error, "Report format is incorrect.")

    @override_settings(CORS_ORIGIN_WHITELIST=["https://rmm.example.com"])
    def test_scheduled_run(self):
        self.assertEqual(
            build_report_link(5, "pdf"),
            "https://rmm.example.com/reports/history/5/?format=pdf",
        )
        schedule = baker.make(
            "reporting.ReportSchedule",
            report_template=self.template,
            format="pdf",
            send_report_email=True,
            email_recipients=["a@example.com"],
            email_settings={"subject": "Subject"},
            dependencies={},
        )
        tasks = SimpleNamespace(email_report=Mock())
        with patch.dict(sys.modules, {"reporting.tasks": tasks}):
            history, error = run_scheduled_report(schedule)
        self.assertIsNone(error)
        schedule.refresh_from_db()
        self.assertIsNotNone(schedule.last_run)
        kwargs = tasks.email_report.delay.call_args.kwargs
        self.assertEqual(
            kwargs["report_link"],
            f"https://rmm.example.com/reports/history/{history.id}/?format=pdf",
        )
        self.assertEqual(kwargs["recipients"], ["a@example.com"])
        self.assertEqual(kwargs["attachment_type"], "pdf")
        self.assertTrue(base64.b64decode(kwargs["attachment"]).startswith(b"%PDF"))
        self.assertEqual(kwargs["subject"], "Subject")
        self.assertIsNone(kwargs["body"])

        self.template.template_md = "{% if %}"
        self.template.save()
        tasks.email_report.reset_mock()
        with patch.dict(sys.modules, {"reporting.tasks": tasks}):
            _, error = run_scheduled_report(schedule)
        self.assertIsNotNone(error)
        tasks.email_report.delay.assert_not_called()

    def test_scheduled_run_uses_owner_scope(self):
        client1 = baker.make("clients.Client")
        agent = baker.make_recipe(
            "agents.agent", site=baker.make("clients.Site", client=client1)
        )
        baker.make_recipe("agents.agent")
        owner = self.create_user_with_roles(["can_view_reports"])
        owner.role.can_view_clients.set([client1])
        self.template.template_md = "{{ data_sources.agents }}"
        self.template.type = "html"
        self.template.template_variables = (
            "data_sources:\n  agents: {model: agent, count: true}"
        )
        self.template.save()
        schedule = baker.make(
            "reporting.ReportSchedule",
            report_template=self.template,
            format="html",
            send_report_email=False,
            dependencies={},
        )

        history, _ = run_scheduled_report(schedule)
        self.assertEqual(history.report_data, "2")
        history, _ = run_scheduled_report(schedule, user=owner)
        self.assertEqual(history.report_data, "1")
        self.assertEqual(history.run_by, owner.username)
        self.assertTrue(agent.pk)

        owner.is_active = False
        owner.save()
        history, error = run_scheduled_report(schedule, user=owner)
        self.assertIn("disabled", error)


class TestSchema(ULRMMTestCase):
    def test_schema(self):
        data = schema.build_query_schema()
        self.assertEqual(data["required"], ["model"])
        names = [name.lower() for name, _ in REPORTING_MODELS]
        self.assertEqual(data["properties"]["model"]["enum"], names)
        self.assertEqual(len(data["oneOf"]), len(names))
        self.assertEqual(
            data["$id"],
            f"https://{settings.ALLOWED_HOSTS[0]}/static/reporting/schemas/query_schema.json",
        )

        agent = data["oneOf"][0]["properties"]
        self.assertEqual(agent["filter"]["properties"]["hostname"], {"type": "string"})
        self.assertEqual(agent["filter"]["properties"]["site"], {"type": "integer"})
        self.assertEqual(
            agent["filter"]["properties"]["site__client__name"], {"type": "string"}
        )
        self.assertIn("^hostname(__[a-zA-Z]+)*$", agent["filter"]["patternProperties"])
        self.assertIn("site", agent["select_related"]["items"]["enum"])
        self.assertIn("site__client", agent["select_related"]["items"]["enum"])
        self.assertEqual(
            agent["properties"]["items"]["enum"], get_property_fields(Agent)
        )
        self.assertIn("json", data["properties"])

        dumped = json.dumps(data)
        for secret in ("snmp_secret", "password", "user__"):
            self.assertNotIn(secret, dumped)

    def test_write(self):
        path = schema.write_query_schema()
        try:
            self.assertTrue(path.endswith("reporting/schemas/query_schema.json"))
            with open(path) as f:
                self.assertEqual(json.load(f)["required"], ["model"])
        finally:
            os.remove(path)
