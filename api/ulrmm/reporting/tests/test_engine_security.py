# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import datetime
import os
import time
from unittest.mock import patch

from django.db import connection
from django.test import override_settings
from jinja2.sandbox import SecurityError
from model_bakery import baker

from agents.models import Agent

from reporting.tests.test_engine_db import AssetRootMixin, model, query
from reporting.utils import (
    InvalidDBOperationException,
    RenderLimitExceeded,
    _statement_timeout,
    generate_html,
    normalize_asset_url,
    parse_variables,
    process_dependencies,
    render_deadline,
    restore_asset_links,
    run_report,
)
from ulrmm.test import ULRMMTestCase


class TestRelationEscapes(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.mine_client = baker.make("clients.Client", name="C1")
        self.other_client = baker.make("clients.Client", name="C2")
        self.mine = baker.make_recipe(
            "agents.agent",
            hostname="mine",
            site=baker.make("clients.Site", client=self.mine_client, name="S1"),
        )
        self.other = baker.make_recipe(
            "agents.agent",
            hostname="OTHER-TENANT",
            site=baker.make("clients.Site", client=self.other_client, name="S2"),
        )

        self.hook = baker.make(
            "core.URLAction",
            name="hook",
            rest_headers='{"Authorization": "Bearer HOOK-SECRET"}',
            rest_body="HOOK-BODY",
        )
        self.script = baker.make(
            "scripts.Script", name="cleanup", env_vars=["TOKEN=SCRIPT-SECRET"]
        )
        self.alert_template = baker.make(
            "alerts.AlertTemplate",
            name="alerts",
            action=self.script,
            action_rest=self.hook,
            action_env_vars=["TOKEN=ENV-SECRET"],
        )
        self.policy = baker.make(
            "automation.Policy", name="shared", alert_template=self.alert_template
        )
        # save() would recompute the alert template from the policies
        Agent.objects.filter(pk__in=[self.mine.pk, self.other.pk]).update(
            policy=self.policy, alert_template=self.alert_template
        )
        self.policy.excluded_agents.add(self.other)

        core = self.coresettings
        core.mesh_token = "MESH-SECRET"
        core.smtp_host_password = "SMTP-SECRET"
        core.server_policy = self.policy
        core.workstation_policy = self.policy
        core.alert_template = self.alert_template
        core.save()

        self.user = self.create_user_with_roles(["can_manage_reports"])
        self.user.role.can_view_clients.set([self.mine_client])
        self.superuser = self.create_user_with_roles(["is_superuser"])

    def assert_refused(self, data_source, users):
        for user in users:
            with self.subTest(data_source=data_source, user=user), self.assertRaises(
                InvalidDBOperationException
            ):
                query(data_source, user)

    def test_core_settings_unreachable(self):
        everyone = (None, self.user, self.superuser)
        for data_source in (
            {
                "model": "policy",
                "values": [
                    "default_server_policy__mesh_token",
                    "default_server_policy__smtp_host_password",
                ],
            },
            {"model": "agent", "values": ["policy__default_server_policy__mesh_token"]},
            {
                "model": "agent",
                "values": ["alert_template__default_alert_template__mesh_token"],
            },
            {
                "model": "policy",
                "filter": {"default_workstation_policy__mesh_token__startswith": "M"},
                "count": True,
            },
            {"model": "policy", "order_by": ["-default_server_policy__mesh_token"]},
            {"model": "policy", "only": ["default_server_policy__pk"]},
        ):
            self.assert_refused(data_source, everyone)

    def test_relations_stay_in_the_role_scope(self):
        for data_source in (
            {"model": "agent", "values": ["hostname", "policy__agents__hostname"]},
            {"model": "policy", "values": ["agents__hostname"]},
            {"model": "policy", "values": ["agents__site__client__name"]},
            {"model": "policy", "values": ["agents"]},
            {"model": "policy", "only": ["excluded_agents__hostname"]},
            {"model": "client", "values": ["sites__name"]},
            {"model": "site", "order_by": ["agents__hostname"]},
            {"model": "agent", "select_related": ["policy__agents"]},
            {
                "model": "policy",
                "filter": {"agents__hostname": "OTHER-TENANT"},
                "count": True,
            },
            {
                "model": "agent",
                "get": {"policy__agents__hostname": "OTHER-TENANT"},
            },
        ):
            self.assert_refused(data_source, [self.user])

        rows = query(
            {
                "model": "agent",
                "values": ["hostname", "site__client__name", "policy__name"],
            },
            self.user,
        )
        self.assertEqual(
            rows,
            [
                {
                    "hostname": "mine",
                    "site__client__name": "C1",
                    "policy__name": "shared",
                    "id": self.mine.pk,
                }
            ],
        )

        rows = query(
            {"model": "policy", "values": ["agents__hostname"]}, self.superuser
        )
        self.assertEqual(
            sorted(row["agents__hostname"] for row in rows), ["OTHER-TENANT", "mine"]
        )

    def test_check_history_is_scoped(self):
        baker.make("checks.CheckHistory", agent_id=self.mine.agent_id, results="mine")
        baker.make("checks.CheckHistory", agent_id=self.other.agent_id, results="other")
        rows = query({"model": "checkhistory"}, self.user)
        self.assertEqual([row["results"] for row in rows], ["mine"])
        self.assertEqual(len(query({"model": "checkhistory"}, self.superuser)), 2)

    def test_models_without_a_scope_fail_closed(self):
        self.assertEqual(len(query({"model": "policy"}, self.user)), 1)
        with patch("reporting.utils.UNSCOPED_MODELS", frozenset()):
            self.assert_refused({"model": "policy"}, [self.user])
            self.assertEqual(len(query({"model": "policy"}, self.superuser)), 1)

    def test_superuser_only_models_through_relations(self):
        baker.make("logs.DebugLog", agent=self.mine, message="debug-secret")
        for data_source in (
            {"model": "agent", "values": ["debuglogs__message"]},
            {"model": "agent", "filter": {"debuglogs__message": "debug-secret"}},
        ):
            self.assert_refused(data_source, [self.user])
        rows = query(
            {"model": "agent", "values": ["debuglogs__message"]}, self.superuser
        )
        self.assertIn("debug-secret", [row["debuglogs__message"] for row in rows])

    def test_key_store_placeholder(self):
        baker.make("core.GlobalKVStore", name="apikey", value="KV-SECRET")
        source = 'k: "{{global.apikey}}"'
        self.assertEqual(parse_variables(source, user=self.user)["k"], source[4:-1])
        html, _ = generate_html(
            "{{ k }}", "plaintext", variables=source, user=self.user
        )
        self.assertNotIn("KV-SECRET", html)

        self.assertEqual(parse_variables(source)["k"], "KV-SECRET")
        self.assertEqual(parse_variables(source, user=self.superuser)["k"], "KV-SECRET")
        self.user.role.can_view_global_keystore = True
        self.user.role.save()
        self.assertEqual(parse_variables(source, user=self.user)["k"], "KV-SECRET")

    def test_url_actions_and_scripts_unreachable(self):
        secrets = ("HOOK-SECRET", "HOOK-BODY", "SCRIPT-SECRET", "ENV-SECRET")
        for data_source in (
            {"model": "agent", "values": ["alert_template__action_rest__rest_headers"]},
            {
                "model": "agent",
                "values": ["alert_template__resolved_action_rest__rest_body"],
            },
            {"model": "policy", "values": ["alert_template__action_env_vars"]},
            {"model": "agent", "values": ["alert_template__action__env_vars"]},
            {"model": "agent", "values": ["alert_template__action_rest__pattern"]},
        ):
            self.assert_refused(data_source, (None, self.superuser))

        for source in (
            "{{ agent.alert_template.action_rest.rest_headers.x }}",
            "{{ agent.policy.alert_template.action_rest.rest_body.x }}",
            "{{ agent.alert_template.action.env_vars[0] }}",
        ):
            with self.subTest(source=source), self.assertRaises(SecurityError):
                generate_html(
                    source, "html", dependencies={"agent": self.mine.agent_id}
                )
        html, _ = generate_html(
            "{{ agent.alert_template.action_env_vars }}|{{ agent.alert_template.name }}|"
            "{{ agent.alert_template.action_rest.rest_headers }}|"
            "{{ agent.alert_template.action.env_vars }}|"
            "{{ agent.alert_template.action_rest.name }}",
            "html",
            dependencies={"agent": self.mine.agent_id},
        )
        self.assertEqual(html, "|alerts|||hook")

        variables = process_dependencies(
            'h: "{{agent.alert_template.action_rest.rest_headers}}"\n'
            'e: "{{agent.alert_template.action_env_vars}}"\n'
            'n: "{{agent.alert_template.name}}"',
            {"agent": self.mine.agent_id},
        )
        self.assertEqual(
            variables["h"], "{{agent.alert_template.action_rest.rest_headers}}"
        )
        self.assertEqual(variables["n"], "alerts")
        for secret in secrets:
            self.assertNotIn(secret, str(variables))

    def test_related_fields_without_secrets_work(self):
        self.alert_template.agent_always_alert = True
        self.alert_template.email_recipients = ["ops@example.com"]
        self.alert_template.check_email_alert_severity = ["error"]
        self.alert_template.task_always_email = True
        self.alert_template.save()
        self.script.description = "cleans up"
        self.script.script_body = "echo cleanup"
        self.script.save()
        check = baker.make_recipe("checks.diskspace_check", agent=self.mine)
        check.script = self.script
        check.save()

        for user in (None, self.user, self.superuser):
            with self.subTest(user=user):
                row = query(
                    {
                        "model": "agent",
                        "filter": {
                            "alert_template__agent_always_alert": True,
                            "alert_template__action__category__isnull": True,
                        },
                        "only": [
                            "hostname",
                            "alert_template__agent_always_alert",
                            "alert_template__email_recipients",
                            "policy__alert_template__task_always_email",
                            "alert_template__action__description",
                        ],
                        "first": True,
                    },
                    user,
                )
                self.assertEqual(
                    row["alert_template__email_recipients"], ["ops@example.com"]
                )
                self.assertTrue(row["policy__alert_template__task_always_email"])
                self.assertEqual(
                    row["alert_template__action__description"], "cleans up"
                )
                row = query(
                    {
                        "model": "client",
                        "values": ["alert_template__check_email_alert_severity"],
                        "first": True,
                    },
                    user,
                )
                self.assertIn("alert_template__check_email_alert_severity", row)
                row = query(
                    {
                        "model": "check",
                        "values": ["script__script_body"],
                        "first": True,
                    },
                    user,
                )
                self.assertEqual(row["script__script_body"], "echo cleanup")

        # reverse relations stay open to unrestricted users only
        baker.make("encryption.EncryptionState", agent=self.mine)
        rows = query(
            {"model": "agent", "values": ["hostname", "encryption_state__id"]},
            self.superuser,
        )
        self.assertEqual(len(rows), 2)
        self.assert_refused(
            {"model": "agent", "values": ["encryption_state__id"]}, [self.user]
        )

    def test_listed_related_fields_still_work(self):
        check = baker.make_recipe("checks.diskspace_check", agent=self.mine)
        check.script = self.script
        check.save()
        field = baker.make("core.CustomField", model="agent", type="text", name="f1")
        baker.make("agents.AgentCustomField", agent=self.mine, field=field)

        self.assertEqual(
            query(
                {"model": "check", "values": ["script__name"], "first": True},
                self.user,
            )["script__name"],
            "cleanup",
        )
        self.assertEqual(
            query(
                {"model": "agentcustomfield", "values": ["field__name"], "first": True},
                self.user,
            )["field__name"],
            "f1",
        )
        self.assertEqual(
            query(
                {"model": "agent", "values": ["alert_template__name"], "first": True},
                self.user,
            )["alert_template__name"],
            "alerts",
        )


def render(source, **context):
    html, _ = generate_html(source, "plaintext", **context)
    return html


@override_settings(REPORTING_MAX_OUTPUT_MB=1)
class TestRenderLimits(ULRMMTestCase):
    def test_single_operations_are_bounded(self):
        for source in (
            "{% set ns = namespace(s='a') %}{% for i in range(40) %}"
            "{% set ns.s = ns.s ~ ns.s %}{% endfor %}{{ ns.s|length }}",
            "{% set ns = namespace(s='a') %}{% for i in range(40) %}"
            "{% set ns.s = ns.s + ns.s %}{% endfor %}{{ ns.s|length }}",
            "{% set ns = namespace(l=[1]) %}{% for i in range(40) %}"
            "{% set ns.l = ns.l + ns.l %}{% endfor %}{{ ns.l|length }}",
            "{% set l = [1] %}{% for i in range(40) %}{% do l.extend(l) %}{% endfor %}",
            "{{ 'a'.ljust(200000000)|length }}",
            "{{ 'a'.center(200000000)|length }}",
            "{{ 'a\tb'.expandtabs(200000000)|length }}",
            "{{ ('a' * 1000).replace('a', 'b' * 2000)|length }}",
            "{{ ('a' * 1000)|replace('a', 'b' * 2000)|length }}",
            "{{ '{:>200000000}'.format('a')|length }}",
            "{{ '{:.200000000f}'.format(1.0)|length }}",
            "{{ '{:{}}'.format('a', 200000000)|length }}",
            "{{ '{0:>200000000}'.format_map({})|length }}",
            "{{ '%200000000s'|format('a')|length }}",
            "{{ ('%200000000s' % 'a')|length }}",
            "{{ ('%*s' % (200000000, 'a'))|length }}",
            "{{ 'a'|center(200000000)|length }}",
            "{{ 'a\nb'|indent(200000000)|length }}",
            "{% set l = [] %}{% for i in range(2000) %}{% do l.append('x' * 1000) %}"
            "{% endfor %}{{ l|join|length }}",
            "{{ ['x' * 100000] * 20 }}",
            "{{ ('x' * 1000).join(['y'] * 2000)|length }}",
            "{% set x %}{% for i in range(3000) %}{{ 'y' * 1000 }}{% endfor %}"
            "{% endset %}{{ x|length }}",
            "{% macro m() %}{% for i in range(3000) %}{{ 'y' * 1000 }}{% endfor %}"
            "{% endmacro %}{{ m()|length }}",
            "{{ (9 ** 25000) * (9 ** 25000) }}",
        ):
            with self.subTest(source=source), self.assertRaises(SecurityError):
                render(source)

    def test_normal_use_still_works(self):
        self.assertEqual(
            render(
                "{{ 'ab' ~ 'cd' }} {{ 'a' + 'b' }} {{ [1] + [2] }} {{ 6 * 7 }} "
                "{{ '%5.2f'|format(3.14159) }} {{ '%d%%' % 5 }} {{ '{:>4}|{:.1f}'.format('a', 2.25) }} "
                "{{ 'a b'|replace(' ', '_') }} {{ [1, 2]|join(',') }} {{ 'x'|center(5) }}|"
                "{{ 'a'.ljust(3) }}|{{ 'a\nb'|indent(2) }}"
            ),
            "abcd ab [1, 2] 42  3.14 5%    a|2.2 a_b 1,2   x  |a  |a\n  b",
        )
        self.assertEqual(
            render(
                "{% set x %}{{ 'y' * 3 }}{% endset %}{{ x }}{{ '{:%Y}'.format(d) }}",
                dependencies={"d": datetime.date(2026, 1, 2)},
            ),
            "yyy2026",
        )

    def test_yaml_alias_bombs(self):
        levels = ["a0: &a0 [x, x, x, x, x, x, x, x, x, x]"]
        for level in range(1, 8):
            items = ", ".join([f"*a{level - 1}"] * 10)
            levels.append(f"a{level}: &a{level} [{items}]")
        bomb = "\n".join(levels) + "\ncharts:\n  c:\n    layout: *a7"
        started = time.monotonic()
        with self.assertRaisesMessage(ValueError, "expand to more than"):
            parse_variables(bomb)
        self.assertLess(time.monotonic() - started, 5)

        with self.assertRaisesMessage(ValueError, "recursive aliases"):
            parse_variables("a: &a [x, *a]")
        with self.assertRaisesMessage(ValueError, "recursive aliases"):
            parse_variables("a: &a {b: {c: *a}}")

        data = parse_variables(
            "base: &base {color: red, size: 2}\nchart:\n  <<: *base\n  size: 3\n"
            "list: [*base, *base]"
        )
        self.assertEqual(data["chart"], {"color": "red", "size": 3})
        self.assertEqual(data["list"], [{"color": "red", "size": 2}] * 2)

    def test_deadline_covers_the_variables(self):
        baker.make_recipe("agents.agent")
        with override_settings(REPORTING_RENDER_TIMEOUT=0), patch(
            "reporting.utils.build_queryset"
        ) as build:
            with self.assertRaises(RenderLimitExceeded):
                generate_html(
                    "x",
                    "html",
                    variables="data_sources:\n  a:\n    model: agent",
                )
        build.assert_not_called()

    def test_statement_timeout(self):
        with connection.cursor() as cursor:
            cursor.execute("SELECT current_setting('statement_timeout')")
            before = cursor.fetchone()[0]

        with override_settings(REPORTING_RENDER_TIMEOUT=60), render_deadline():
            with _statement_timeout(), connection.cursor() as cursor:
                cursor.execute("SELECT current_setting('statement_timeout')")
                self.assertNotEqual(cursor.fetchone()[0], before)
        with override_settings(REPORTING_RENDER_TIMEOUT=0.3), render_deadline():
            with self.assertRaisesMessage(RenderLimitExceeded, "data query"):
                with _statement_timeout(), connection.cursor() as cursor:
                    cursor.execute("SELECT pg_sleep(3)")

        with connection.cursor() as cursor:
            cursor.execute("SELECT current_setting('statement_timeout')")
            self.assertEqual(cursor.fetchone()[0], before)
            cursor.execute("SELECT 1")


class TestHistoryFormats(AssetRootMixin, ULRMMTestCase):
    def setUp(self):
        super().setUp()
        self.asset = self.make_asset("img/logo.png", b"png")
        self.template = baker.make(
            "reporting.ReportTemplate",
            name="logo",
            type="html",
            template_md=f'<img src="asset://{self.asset.id}">',
            template_variables="",
        )

    def test_history_keeps_asset_links(self):
        output, error, history = run_report(self.template, format="html")
        self.assertIsNone(error)
        self.assertIn("https://api.example.com/reporting/assets/img/logo.png", output)
        self.assertEqual(history.report_data, f'<img src="asset://{self.asset.id}">')

        with patch("reporting.utils.generate_pdf", return_value=b"%PDF") as pdf:
            output, error, history = run_report(self.template, format="pdf")
        self.assertEqual(output, b"%PDF")
        self.assertIn("file://", pdf.call_args.args[0])
        self.assertEqual(history.report_data, f'<img src="asset://{self.asset.id}">')

    def test_older_rows_are_restored(self):
        stored = f'<img src="asset://{self.asset.id}">'
        local = os.path.join(self.asset_root, "gone.png")
        for format in ("html", "pdf"):
            legacy = (
                normalize_asset_url(stored, format) + f' <img src="file://{local}">'
            )
            with self.subTest(format=format):
                restored = restore_asset_links(legacy)
                self.assertEqual(restored, stored + ' <img src="">')
                self.assertNotIn(self.asset_root, normalize_asset_url(restored, "html"))
                self.assertIn(self.asset_root, normalize_asset_url(restored, "pdf"))
        self.assertEqual(model("ReportAsset").objects.count(), 1)
