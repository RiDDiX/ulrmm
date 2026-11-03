# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import base64
import io
import json
import os
import tempfile
import uuid
import zipfile
from importlib import import_module
from unittest.mock import patch

from django.apps import apps
from django.core.files.uploadedfile import SimpleUploadedFile
from django.db import connection
from django.test import override_settings
from markupsafe import Markup
from model_bakery import baker

from logs.models import AuditLog, DebugLog
from reporting.models import ReportAsset, ReportDataQuery, ReportHistory
from reporting.models import ReportHTMLTemplate, ReportSchedule, ReportTemplate
from reporting.utils import DatabaseText
from reporting.views import FRAME_MAX, describe_variables
from ulrmm.test import LOCMEM_CACHE, ULRMMTestCase

from .test_engine_db import AssetRootMixin

base_url = "/reporting"


def bundle(**extra):
    template = dict(name="test_template", type="markdown", template_md="# Test MD")
    template["depends_on"] = ["some_dependency"]
    return json.dumps({"template": template, **extra})


def b64(content: bytes) -> str:
    return base64.b64encode(content).decode()


class TestPermissions(AssetRootMixin, ULRMMTestCase):
    def setUp(self):
        super().setUp()
        self.authenticate()
        self.template = baker.make(
            "reporting.ReportTemplate", name="t", template_md="text", type="html"
        )
        self.history = baker.make(
            "reporting.ReportHistory", report_template=self.template, run_by="john"
        )
        self.schedule = baker.make(
            "reporting.ReportSchedule",
            report_template=self.template,
            schedule=baker.make("core.Schedule"),
            dependencies={},
        )

    def routes(self):
        t, h, s = self.template.pk, self.history.pk, self.schedule.pk
        return {
            "get": [
                "/templates/",
                f"/templates/{t}/",
                "/htmltemplates/",
                "/dataqueries/",
                "/assets/",
                "/assets/all/",
                "/assets/download/?path=x.txt",
                "/queryschema/",
                "/schedules/",
                f"/schedules/{s}/",
                "/history/",
            ],
            "manage": [
                ("post", "/templates/"),
                ("put", f"/templates/{t}/"),
                ("delete", f"/templates/{t}/"),
                ("post", "/templates/preview/"),
                ("post", "/templates/preview/analysis/"),
                ("post", "/templates/import/"),
                ("put", "/assets/rename/"),
                ("post", "/assets/newfolder/"),
                ("post", "/assets/delete/"),
                ("post", "/assets/upload/"),
                ("post", "/htmltemplates/"),
                ("post", "/dataqueries/"),
                ("post", "/schedules/"),
                ("put", f"/schedules/{s}/"),
                ("delete", f"/schedules/{s}/"),
                ("post", f"/schedules/{s}/run/"),
                ("delete", f"/history/{h}/"),
            ],
            "generate": [
                f"/templates/{t}/run/",
                f"/templates/{t}/export/",
                f"/templates/{t}/email/",
                f"/history/{h}/run/",
                "/frame/",
            ],
        }

    def test_anonymous_gets_401(self):
        routes = self.routes()
        calls = [("get", url) for url in routes["get"]] + routes["manage"]
        calls += [("post", url) for url in routes["generate"]]
        for method, url in calls:
            with self.subTest(url=url, method=method):
                self.check_not_authenticated(method, f"{base_url}{url}")
        # unsupported method, still 401 first
        self.check_not_authenticated("post", f"{base_url}/assets/all/")

    def test_no_role_gets_403(self):
        routes = self.routes()
        self.client.force_authenticate(user=baker.make("accounts.User"))
        calls = [("get", url) for url in routes["get"]] + routes["manage"]
        calls += [("post", url) for url in routes["generate"]]
        for method, url in calls:
            with self.subTest(url=url, method=method):
                self.check_not_authorized(method, f"{base_url}{url}")
        # unsupported method, still 403 before 405
        self.check_not_authorized("post", f"{base_url}/assets/all/")

    def test_view_only_user(self):
        routes = self.routes()
        user = self.create_user_with_roles(["can_view_reports"])
        self.client.force_authenticate(user=user)
        for url in routes["get"]:
            with self.subTest(url=url):
                self.check_authorized("get", f"{base_url}{url}")
        for method, url in routes["manage"]:
            with self.subTest(url=url, method=method):
                self.check_not_authorized(method, f"{base_url}{url}")
        for url in routes["generate"]:
            with self.subTest(url=url):
                self.check_authorized("post", f"{base_url}{url}", {"format": "x"})

    def test_superusers_pass(self):
        for method, url in self.routes()["manage"][:4]:
            with self.subTest(url=url):
                self.check_authorized_superuser(method, f"{base_url}{url}")

    def test_unsupported_method_gives_405(self):
        r = self.client.post(f"{base_url}/assets/all/")
        self.assertEqual(r.status_code, 405)


class TestReportTemplates(ULRMMTestCase):
    def setUp(self):
        self.authenticate()

    def test_list_and_filter(self):
        r = self.client.get(f"{base_url}/templates/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data, [])

        baker.make("reporting.ReportTemplate", depends_on=["agent"], _quantity=3)
        baker.make("reporting.ReportTemplate", depends_on=["client"], _quantity=2)
        r = self.client.get(f"{base_url}/templates/")
        self.assertEqual(len(r.data), 5)
        r = self.client.get(f"{base_url}/templates/", {"dependsOn[]": ["agent"]})
        self.assertEqual(len(r.data), 3)
        r = self.client.get(
            f"{base_url}/templates/", {"dependsOn[]": ["agent", "client"]}
        )
        self.assertEqual(len(r.data), 5)

    def test_create(self):
        data = {"name": "Test Template", "template_md": "Template Text"}
        r = self.client.post(f"{base_url}/templates/", data, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data["name"], "Test Template")
        template = ReportTemplate.objects.get(name="Test Template")
        self.assertEqual(template.type, "markdown")
        self.assertEqual(template.template_variables, "")
        self.assertEqual(template.depends_on, [])
        self.assertEqual(template.created_by, "john")

        r = self.client.post(f"{base_url}/templates/", data, format="json")
        self.assertEqual(r.status_code, 400)
        self.assertIn("name", r.data)
        r = self.client.post(f"{base_url}/templates/", {"name": "x"}, format="json")
        self.assertEqual(r.status_code, 400)
        r = self.client.post(
            f"{base_url}/templates/",
            {"name": "y", "template_md": "z", "template_html": 999},
            format="json",
        )
        self.assertEqual(r.status_code, 400)
        self.assertIn("template_html", r.data)

    def test_reserved_dependency_names(self):
        data = {"name": "n", "template_md": "md", "depends_on": ["client", "charts"]}
        r = self.client.post(f"{base_url}/templates/", data, format="json")
        self.assertEqual(r.status_code, 400)
        self.assertIn("depends_on", r.data)
        data["depends_on"] = ["client", "extra"]
        r = self.client.post(f"{base_url}/templates/", data, format="json")
        self.assertEqual(r.status_code, 200)
        r = self.client.put(
            f"{base_url}/templates/{r.data['id']}/",
            {"depends_on": ["data_sources"]},
            format="json",
        )
        self.assertEqual(r.status_code, 400)
        self.assertEqual(ReportTemplate.objects.get().depends_on, ["client", "extra"])

    def test_audit_fields_are_read_only(self):
        data = {"name": "n", "template_md": "md", "created_by": "mallory"}
        r = self.client.post(f"{base_url}/templates/", data, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(ReportTemplate.objects.get().created_by, "john")

    def test_get_update_delete(self):
        template = baker.make(
            "reporting.ReportTemplate", name="old", template_md="keep"
        )
        url = f"{base_url}/templates/{template.pk}/"
        r = self.client.get(url)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data["id"], template.pk)
        self.assertEqual(self.client.get(f"{base_url}/templates/999/").status_code, 404)

        r = self.client.put(url, {"name": "Updated name"}, format="json")
        self.assertEqual(r.status_code, 200)
        template.refresh_from_db()
        self.assertEqual(template.name, "Updated name")
        self.assertEqual(template.template_md, "keep")

        baker.make(
            "reporting.ReportSchedule",
            report_template=template,
            schedule=baker.make("core.Schedule"),
        )
        baker.make("reporting.ReportHistory", report_template=template, _quantity=2)
        self.assertEqual(self.client.delete(url).status_code, 200)
        self.assertFalse(ReportTemplate.objects.exists())
        self.assertFalse(ReportSchedule.objects.exists())
        self.assertFalse(ReportHistory.objects.exists())

    def test_edits_are_audited(self):
        template = baker.make("reporting.ReportTemplate", name="a", template_md="1")
        url = f"{base_url}/templates/{template.pk}/"
        self.client.put(url, {"template_md": "2"}, format="json")
        entry = AuditLog.objects.filter(object_type="reporttemplate").last()
        self.assertEqual(entry.action, "modify")
        self.assertNotEqual(
            entry.before_value["template_md_sha256"],
            entry.after_value["template_md_sha256"],
        )
        self.assertNotIn("template_md", entry.after_value)


class TestRunReport(AssetRootMixin, ULRMMTestCase):
    def setUp(self):
        super().setUp()
        self.authenticate()
        self.template = baker.make(
            "reporting.ReportTemplate",
            name="Report",
            template_md="Report text",
            type="markdown",
        )
        self.url = f"{base_url}/templates/{self.template.pk}/run/"

    def test_html(self):
        r = self.client.post(
            self.url, {"format": "html", "dependencies": {}}, format="json"
        )
        self.assertEqual(r.status_code, 200)
        self.assertIn("Report text", r.data)
        history = ReportHistory.objects.get()
        self.assertEqual(history.run_by, "john")
        self.assertIsNone(history.error_data)

    def test_pdf(self):
        r = self.client.post(
            self.url, {"format": "pdf", "dependencies": {}}, format="json"
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r["Content-Type"], "application/pdf")
        self.assertIn('filename="Report.pdf"', r["Content-Disposition"])
        self.assertTrue(r.content.startswith(b"%PDF"))

    def test_bad_input(self):
        r = self.client.post(self.url, {"format": "invalid_format"}, format="json")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.data, "Report format is incorrect.")
        r = self.client.post(self.url, {}, format="json")
        self.assertEqual(r.status_code, 400)
        r = self.client.post(self.url, [1, 2], format="json")
        self.assertEqual(r.status_code, 400)
        r = self.client.post(
            self.url, {"format": "html", "dependencies": [1]}, format="json"
        )
        self.assertEqual(r.status_code, 400)
        self.assertFalse(ReportHistory.objects.exists())

        # missing dependencies count as none
        r = self.client.post(self.url, {"format": "html"}, format="json")
        self.assertEqual(r.status_code, 200)

    def test_syntax_error(self):
        self.template.template_md = "{{invalid}"
        self.template.save()
        r = self.client.post(
            self.url, {"format": "html", "dependencies": {}}, format="json"
        )
        self.assertEqual(r.status_code, 400)
        self.assertTrue(r.data.startswith("Line 1:"))
        history = ReportHistory.objects.get()
        self.assertEqual(history.report_data, "")
        self.assertTrue(history.error_data)

    def test_pipeline_arguments(self):
        with patch(
            "reporting.views.run_report", return_value=("<b>x</b>", None, None)
        ) as run:
            r = self.client.post(
                self.url, {"format": "html", "dependencies": {"client": 1}}, "json"
            )
        self.assertEqual(r.data, "<b>x</b>")
        run.assert_called_once_with(
            template=self.template,
            dependencies={"client": 1},
            format="html",
            user=self.john,
        )

    def test_unknown_and_foreign_dependencies(self):
        r = self.client.post(
            self.url,
            {"format": "html", "dependencies": {"agent": "missing"}},
            format="json",
        )
        self.assertEqual(r.status_code, 400)
        self.assertIn("does not exist", r.data)
        self.assertTrue(ReportHistory.objects.get().error_data)

        # objects outside the user's role look like unknown ones
        visible = baker.make("clients.Client")
        hidden = baker.make("clients.Client")
        user = self.create_user_with_roles(["can_view_reports"])
        user.role.can_view_clients.set([visible])
        self.client.force_authenticate(user=user)
        for client, status in ((visible, 200), (hidden, 400)):
            r = self.client.post(
                self.url,
                {"format": "html", "dependencies": {"client": client.pk}},
                format="json",
            )
            self.assertEqual(r.status_code, status)

    def test_errors_hide_internals(self):
        with patch("reporting.utils.generate_html", side_effect=OSError("/opt/x")):
            r = self.client.post(
                self.url, {"format": "html", "dependencies": {}}, format="json"
            )
        self.assertEqual(r.status_code, 400)
        self.assertNotIn("/opt", r.data)


@override_settings(CORS_ORIGIN_WHITELIST=["https://rmm.example.com"])
class TestEmailReport(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.template = baker.make(
            "reporting.ReportTemplate", name="Mail", template_md="Body", type="html"
        )
        self.url = f"{base_url}/templates/{self.template.pk}/email/"
        self.data = {
            "format": "html",
            "dependencies": {},
            "email_recipients": ["a@example.com"],
            "email_settings": {"subject": "Hi", "body": "See attached"},
        }

    @patch("reporting.tasks.email_report.delay")
    def test_email(self, delay):
        r = self.client.post(self.url, self.data, format="json")
        self.assertEqual(r.status_code, 200)
        history = ReportHistory.objects.get()
        delay.assert_called_once_with(
            template_name="Mail",
            report_link=f"https://rmm.example.com/reports/history/{history.id}/?format=html",
            recipients=["a@example.com"],
            attachment="Body",
            attachment_type="html",
            subject="Hi",
            body="See attached",
            attachment_name=None,
            attachment_extension=None,
            include_report_link=None,
        )

    @patch("reporting.tasks.email_report.delay")
    def test_empty_recipients_use_the_defaults(self, delay):
        r = self.client.post(
            self.url, {**self.data, "email_recipients": []}, format="json"
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(delay.call_args.kwargs["recipients"], [])

    @patch("reporting.tasks.email_report.delay")
    def test_pdf_attachment_is_base64(self, delay):
        r = self.client.post(self.url, {**self.data, "format": "pdf"}, format="json")
        self.assertEqual(r.status_code, 200)
        attachment = delay.call_args.kwargs["attachment"]
        self.assertTrue(base64.b64decode(attachment).startswith(b"%PDF"))

    @patch("reporting.tasks.email_report.delay")
    def test_failed_render_sends_nothing(self, delay):
        self.template.template_md = "{% if %}"
        self.template.save()
        r = self.client.post(self.url, self.data, format="json")
        self.assertEqual(r.status_code, 400)
        delay.assert_not_called()

    @patch("reporting.tasks.email_report.delay")
    def test_validation(self, delay):
        bad = [
            {"format": "docx"},
            {"email_recipients": ["not an email"]},
            {"email_settings": {"subject": "a\r\nBcc: x@example.com"}},
            {"email_settings": {"attachment_name": "a\nb"}},
            {"email_settings": {"attachment_extension": "../exe"}},
            {"email_settings": {"attachment_extension": "toolongext"}},
            {"email_settings": {"include_report_link": "yes"}},
            {"email_settings": []},
            {"dependencies": "x"},
        ]
        for change in bad:
            with self.subTest(change=change):
                r = self.client.post(self.url, {**self.data, **change}, format="json")
                self.assertEqual(r.status_code, 400)
        data = dict(self.data)
        del data["email_recipients"]
        self.assertEqual(self.client.post(self.url, data, "json").status_code, 400)
        delay.assert_not_called()
        self.assertFalse(ReportHistory.objects.exists())


class TestPreview(AssetRootMixin, ULRMMTestCase):
    def setUp(self):
        super().setUp()
        self.authenticate()
        self.url = f"{base_url}/templates/preview/"
        self.data = {
            "template_md": "<p>hello</p>",
            "type": "html",
            "template_css": "",
            "template_html": None,
            "template_variables": "",
            "dependencies": {},
            "format": "html",
            "debug": False,
        }

    def test_html_and_no_history(self):
        with patch("reporting.views.generate_html", return_value=("<html></html>", {})):
            r = self.client.post(self.url, self.data, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data, "<html></html>")
        self.assertFalse(ReportHistory.objects.exists())

    def test_pdf(self):
        with patch("reporting.views.generate_pdf", return_value=b"%PDF-x") as pdf:
            r = self.client.post(self.url, {**self.data, "format": "pdf"}, "json")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r["Content-Type"], "application/pdf")
        self.assertIn('filename="preview.pdf"', r["Content-Disposition"])
        self.assertEqual(r.content, b"%PDF-x")
        pdf.assert_called_once()

    def test_debug(self):
        agent = baker.make_recipe("agents.agent")
        r = self.client.post(
            self.url,
            {
                **self.data,
                "template_md": "{{ agent.hostname }} {{ when }}",
                "template_variables": "when: !now\nname: <b>",
                "dependencies": {"agent": agent.agent_id},
                "debug": True,
            },
            format="json",
        )
        self.assertEqual(r.status_code, 200)
        self.assertIn(agent.hostname, r.data["template"])
        variables = json.loads(r.content)["variables"]
        self.assertEqual(variables["agent"]["hostname"], agent.hostname)
        self.assertEqual(variables["agent"]["agent_id"], agent.agent_id)
        self.assertEqual(variables["name"], "<b>")
        # model fields by field name, the way model_to_dict gives them
        self.assertEqual(variables["agent"]["site"], agent.site_id)
        self.assertIn("policy", variables["agent"])
        self.assertNotIn("site_id", variables["agent"])
        self.assertNotIn("created_time", variables["agent"])
        self.assertTrue(variables["when"].endswith("Z"))

    def test_validation_and_errors(self):
        data = dict(self.data)
        del data["type"]
        r = self.client.post(self.url, {**data, "format": "invalid_format"}, "json")
        self.assertEqual(r.status_code, 400)

        with patch(
            "reporting.views.generate_html",
            side_effect=ValueError("Some template error"),
        ):
            r = self.client.post(self.url, self.data, format="json")
        self.assertEqual(r.status_code, 400)
        self.assertIn("Some template error", r.data)

        r = self.client.post(
            self.url, {**self.data, "template_md": "{% if %}"}, format="json"
        )
        self.assertEqual(r.status_code, 400)
        self.assertTrue(r.data.startswith("Line 1:"))

    def test_asset_urls(self):
        asset = self.make_asset("img/logo.png")
        data = {**self.data, "template_md": f'<img src="asset://{asset.id}">'}
        r = self.client.post(self.url, data, format="json")
        self.assertIn(f"/reporting/assets/img/logo.png?id={asset.id}", r.data)

        with patch("reporting.views.generate_pdf", return_value=b"%PDF") as pdf:
            self.client.post(self.url, {**data, "format": "pdf"}, format="json")
        expected = f"file://{os.path.join(self.asset_root, 'img/logo.png')}"
        self.assertIn(expected, pdf.call_args.args[0])

    def test_runs_with_the_users_scope(self):
        client = baker.make("clients.Client")
        baker.make_recipe(
            "agents.agent", site=baker.make("clients.Site", client=client)
        )
        baker.make_recipe("agents.agent")
        user = self.create_user_with_roles(["can_manage_reports"])
        user.role.can_view_clients.set([client])
        self.client.force_authenticate(user=user)
        data = {
            **self.data,
            "template_md": "{{ data_sources.agents }}",
            "template_variables": "data_sources:\n  agents: {model: agent, count: true}",
        }
        r = self.client.post(self.url, data, format="json")
        self.assertEqual(r.data, "1")

        # superuser-only models fail instead of running unscoped
        data["template_variables"] = (
            "data_sources:\n  kv: {model: globalkvstore, count: true}"
        )
        r = self.client.post(self.url, data, format="json")
        self.assertEqual(r.status_code, 400)


class TestVariableAnalysis(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.url = f"{base_url}/templates/preview/analysis/"

    def test_analysis(self):
        variables = "user:\n  name: Alice\n  roles: [admin, user]\ncount: 1"
        r = self.client.post(self.url, {"variables": variables}, format="json")
        self.assertEqual(r.status_code, 200)
        expected = {"user": "Object", "user.name": "str", "user.roles[0]": "str"}
        expected.update({"user.roles": "Array (2 Results)", "count": "int"})
        self.assertEqual(r.data, expected)
        r = self.client.post(
            self.url, {"variables": {"count": 1}, "dependencies": {}}, format="json"
        )
        self.assertEqual(r.data, {"count": "int"})

    def test_markup_and_database_text_are_str(self):
        self.assertEqual(
            describe_variables(
                {"charts": {"p": Markup("<div>")}, "t": DatabaseText("x")}
            ),
            {"charts": "Object", "charts.p": "str", "t": "str"},
        )

    def test_queries_are_limited_and_scoped(self):
        baker.make_recipe("agents.agent", _quantity=3)
        variables = "data_sources:\n  agents: {model: agent, only: [hostname]}"
        r = self.client.post(self.url, {"variables": variables}, format="json")
        self.assertEqual(r.data["data_sources.agents"], "Array (1 Results)")
        self.assertEqual(r.data["data_sources.agents[0].hostname"], "str")

        user = self.create_user_with_roles(["can_manage_reports"])
        user.role.can_view_clients.set([baker.make("clients.Client")])
        self.client.force_authenticate(user=user)
        r = self.client.post(self.url, {"variables": variables}, format="json")
        self.assertEqual(r.data["data_sources.agents"], "Array (0 Results)")

    def test_empty_and_missing(self):
        r = self.client.post(self.url, {"variables": ""}, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertIsNone(r.data)
        r = self.client.post(self.url, {}, format="json")
        self.assertEqual(r.status_code, 400)
        r = self.client.post(self.url, {"variables": "a: ["}, format="json")
        self.assertEqual(r.status_code, 400)


class TestExportImport(AssetRootMixin, ULRMMTestCase):
    def setUp(self):
        super().setUp()
        self.authenticate()
        self.import_url = f"{base_url}/templates/import/"

    def test_export(self):
        base = baker.make("reporting.ReportHTMLTemplate", name="base", html="<b>")
        template = baker.make(
            "reporting.ReportTemplate",
            name="exp",
            template_md="md",
            template_html=base,
            depends_on=["agent"],
        )
        with patch("reporting.views.base64_encode_assets", return_value=["x"]):
            r = self.client.post(f"{base_url}/templates/{template.pk}/export/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data["base_template"], {"name": "base", "html": "<b>"})
        self.assertEqual(
            r.data["template"],
            {
                "name": "exp",
                "template_css": None,
                "template_md": "md",
                "type": "markdown",
                "depends_on": ["agent"],
                "template_variables": "",
            },
        )
        self.assertEqual(r.data["assets"], ["x"])

        template.template_html = None
        template.save()
        r = self.client.post(f"{base_url}/templates/{template.pk}/export/")
        self.assertIsNone(r.data["base_template"])

    def test_export_assets(self):
        one = self.make_asset("one.png", b"1")
        two = self.make_asset("img/two.png", b"2")
        missing = uuid.uuid4()
        template = baker.make(
            "reporting.ReportTemplate",
            template_md=f"asset://{one.id} asset://{two.id} asset://{one.id} asset://{missing}",
        )
        r = self.client.post(f"{base_url}/templates/{template.pk}/export/")
        self.assertEqual(len(r.data["assets"]), 2)
        files = {a["name"]: base64.b64decode(a["file"]) for a in r.data["assets"]}
        self.assertEqual(files, {"one.png": b"1", "img/two.png": b"2"})

        # the import rewrites asset ids in css and variables, so they are exported
        font = self.make_asset("font.woff2", b"font")
        logo = self.make_asset("logo.png", b"logo")
        template = baker.make(
            "reporting.ReportTemplate",
            template_md="md",
            template_css=f"@font-face {{ src: url(asset://{font.id}); }}",
            template_variables=f"logo: asset://{logo.id}",
        )
        r = self.client.post(f"{base_url}/templates/{template.pk}/export/")
        self.assertEqual(
            sorted(a["name"] for a in r.data["assets"]), ["font.woff2", "logo.png"]
        )

    def test_import(self):
        r = self.client.post(self.import_url, {"template": bundle()}, format="json")
        self.assertEqual(r.status_code, 200)
        template = ReportTemplate.objects.get(name="test_template")
        self.assertEqual(template.depends_on, ["some_dependency"])

        # a second import without overwrite gets a suffixed name
        with patch("reporting.utils.get_random_string", return_value="randomized"):
            r = self.client.post(self.import_url, {"template": bundle()}, "json")
        self.assertTrue(
            ReportTemplate.objects.filter(name="test_template_randomized").exists()
        )

    def test_import_with_base_and_overwrite(self):
        data = bundle(base_template={"name": "base_test_template", "html": "<div>"})
        for _ in range(2):
            r = self.client.post(
                self.import_url, {"template": data, "overwrite": True}, format="json"
            )
            self.assertEqual(r.status_code, 200)
        self.assertEqual(
            ReportHTMLTemplate.objects.filter(
                name__startswith="base_test_template"
            ).count(),
            1,
        )
        template = ReportTemplate.objects.get(name__startswith="test_template")
        self.assertEqual(template.template_html.name, "base_test_template")

    def test_overwrite_false_in_form_data(self):
        self.client.post(self.import_url, {"template": bundle()}, format="json")
        r = self.client.post(
            self.import_url, {"template": bundle(), "overwrite": "false"}
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(ReportTemplate.objects.count(), 2)
        r = self.client.post(self.import_url, {"template": bundle(), "overwrite": "1"})
        self.assertEqual(ReportTemplate.objects.count(), 2)

    def test_import_assets(self):
        one, two = str(uuid.uuid4()), str(uuid.uuid4())
        data = bundle(
            assets=[
                {"id": one, "name": "a.png", "file": b64(b"aaa")},
                {"id": two, "name": "img/b.png", "file": b64(b"bbb")},
            ]
        )
        r = self.client.post(self.import_url, {"template": data}, format="json")
        self.assertEqual(r.status_code, 200)
        for asset_id, content in ((one, b"aaa"), (two, b"bbb")):
            asset = ReportAsset.objects.get(id=asset_id)
            with open(os.path.join(self.asset_root, asset.file.name), "rb") as f:
                self.assertEqual(f.read(), content)

    def test_import_name_conflict_and_existing_ids(self):
        ids = [str(uuid.uuid4()) for _ in range(3)]
        assets = [
            {"id": ids[0], "name": "img/same.png", "file": b64(b"1")},
            {"id": ids[1], "name": "img/same.png", "file": b64(b"2")},
            {"id": ids[2], "name": "other.png", "file": b64(b"3")},
        ]
        template = {
            "name": "with_assets",
            "template_md": f"asset://{ids[2]}",
        }
        data = json.dumps({"template": template, "assets": assets})
        r = self.client.post(self.import_url, {"template": data}, format="json")
        self.assertEqual(r.status_code, 200)
        second = ReportAsset.objects.get(id=ids[1])
        self.assertNotEqual(second.file.name, "img/same.png")
        self.assertTrue(second.file.name.startswith("img/same_"))

        # the same export again on this instance: the import still works and
        # a changed file gets a new id that the template points to
        assets[2]["file"] = b64(b"changed")
        data = json.dumps({"template": template, "assets": assets})
        r = self.client.post(self.import_url, {"template": data}, format="json")
        self.assertEqual(r.status_code, 200)
        imported = ReportTemplate.objects.get(pk=r.data["id"])
        new_id = imported.template_md.removeprefix("asset://")
        self.assertNotEqual(new_id, ids[2])
        self.assertTrue(ReportAsset.objects.filter(id=new_id).exists())

    def test_import_failures_roll_back(self):
        data = json.loads(bundle(base_template={"name": "b", "html": "<p>"}))
        del data["template"]["name"]
        r = self.client.post(
            self.import_url, {"template": json.dumps(data)}, format="json"
        )
        self.assertEqual(r.status_code, 400)
        self.assertIn("name", r.data)

        bad_assets = bundle(
            base_template={"name": "b", "html": "<p>"},
            assets=[
                {"id": str(uuid.uuid4()), "name": "1.png", "file": b64(b"1")},
                {"id": str(uuid.uuid4()), "name": "2.png", "file": b64(b"2")},
                {"id": str(uuid.uuid4()), "name": "3.png", "file": "not base64!"},
            ],
        )
        r = self.client.post(self.import_url, {"template": bad_assets}, "json")
        self.assertEqual(r.status_code, 400)
        self.assertFalse(ReportTemplate.objects.exists())
        self.assertFalse(ReportHTMLTemplate.objects.exists())
        self.assertFalse(ReportAsset.objects.exists())
        self.assertEqual(os.listdir(self.asset_root), [])

    def test_import_whitelists_fields(self):
        data = json.loads(bundle())
        data["template"].update({"id": 777, "created_by": "mallory"})
        r = self.client.post(
            self.import_url, {"template": json.dumps(data)}, format="json"
        )
        self.assertEqual(r.status_code, 200)
        template = ReportTemplate.objects.get()
        self.assertNotEqual(template.pk, 777)
        self.assertNotEqual(template.created_by, "mallory")

        data["template"]["type"] = "exe"
        r = self.client.post(
            self.import_url,
            {"template": json.dumps(data), "overwrite": True},
            format="json",
        )
        self.assertEqual(r.status_code, 400)

    def test_import_bad_input(self):
        for body in ({}, {"template": "{not json"}, {"template": 5}):
            with self.subTest(body=body):
                r = self.client.post(self.import_url, body, format="json")
                self.assertEqual(r.status_code, 400)
        # the decoder message is passed on as it is
        broken = "{\n'name': 'x'}"
        with self.assertRaises(ValueError) as decoded:
            json.loads(broken)
        r = self.client.post(self.import_url, {"template": broken}, format="json")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.data, str(decoded.exception))
        self.assertIn("line 2 column 1", r.data)
        with override_settings(REPORTING_MAX_IMPORT_MB=0):
            r = self.client.post(self.import_url, {"template": bundle()}, "json")
        self.assertEqual(r.status_code, 400)
        r = self.client.post(
            self.import_url,
            {
                "template": bundle(
                    assets=[{"id": str(uuid.uuid4()), "name": "x.html", "file": ""}]
                )
            },
            format="json",
        )
        self.assertEqual(r.status_code, 400)

    def test_import_asset_path_errors_are_named(self):
        asset = {"id": str(uuid.uuid4()), "name": "../x.png", "file": b64(b"png")}
        r = self.client.post(
            self.import_url, {"template": bundle(assets=[asset])}, format="json"
        )
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.data, "Asset ../x.png has an invalid path")
        self.assertFalse(ReportTemplate.objects.exists())


class TestHTMLTemplatesAndQueries(ULRMMTestCase):
    def setUp(self):
        self.authenticate()

    def test_html_templates(self):
        url = f"{base_url}/htmltemplates/"
        baker.make("reporting.ReportHTMLTemplate", name="one")
        r = self.client.get(url)
        self.assertEqual([t["name"] for t in r.data], ["one"])

        data = {"name": "Test Template", "html": "<div>Test HTML</div>"}
        self.assertEqual(self.client.post(url, data, "json").status_code, 200)
        self.assertEqual(self.client.post(url, {"name": ""}, "json").status_code, 400)
        template = ReportHTMLTemplate.objects.get(name="Test Template")

        detail = f"{url}{template.pk}/"
        self.assertEqual(self.client.get(detail).status_code, 200)
        self.assertEqual(self.client.get(f"{url}999/").status_code, 404)
        self.assertEqual(self.client.put(f"{url}999/", {}, "json").status_code, 404)
        self.assertEqual(self.client.delete(f"{url}999/").status_code, 404)
        r = self.client.put(detail, {"name": "Renamed"}, format="json")
        self.assertEqual(r.status_code, 200)
        template.refresh_from_db()
        self.assertEqual(template.name, "Renamed")
        self.assertEqual(self.client.put(detail, {"name": ""}, "json").status_code, 400)
        self.assertEqual(self.client.delete(detail).status_code, 200)
        self.assertFalse(ReportHTMLTemplate.objects.filter(pk=template.pk).exists())

    def test_delete_base_template_in_use(self):
        base = baker.make("reporting.ReportHTMLTemplate", name="base")
        baker.make("reporting.ReportTemplate", name="uses it", template_html=base)
        r = self.client.delete(f"{base_url}/htmltemplates/{base.pk}/")
        self.assertEqual(r.status_code, 400)
        self.assertIn("uses it", r.data)
        self.assertTrue(ReportHTMLTemplate.objects.exists())

    def test_data_queries(self):
        url = f"{base_url}/dataqueries/"
        baker.make("reporting.ReportDataQuery", name="q", json_query={})
        self.assertEqual(len(self.client.get(url).data), 1)

        data = {"name": "Test Data Query", "json_query": {"test": "value"}}
        self.assertEqual(self.client.post(url, data, "json").status_code, 200)
        self.assertEqual(self.client.post(url, {"name": ""}, "json").status_code, 400)
        query = ReportDataQuery.objects.get(name="Test Data Query")
        self.assertEqual(query.json_query, {"test": "value"})

        detail = f"{url}{query.pk}/"
        self.assertEqual(self.client.get(detail).status_code, 200)
        self.assertEqual(self.client.get(f"{url}9999/").status_code, 404)
        r = self.client.put(
            detail, {"name": "New", "json_query": {"model": "agent"}}, format="json"
        )
        self.assertEqual(r.status_code, 200)
        query.refresh_from_db()
        self.assertEqual((query.name, query.json_query), ("New", {"model": "agent"}))
        self.assertEqual(self.client.put(detail, {"name": ""}, "json").status_code, 400)
        self.assertEqual(self.client.delete(detail).status_code, 200)
        self.assertEqual(self.client.delete(detail).status_code, 404)

    def test_query_schema(self):
        url = f"{base_url}/queryschema/"
        with tempfile.TemporaryDirectory() as tmp:
            with override_settings(BASE_DIR=tmp, STATICFILES_DIRS=[tmp]):
                # without the generated file the schema is built on the spot
                r = self.client.get(url)
                self.assertEqual(r.status_code, 200)
                self.assertIn("agent", r.data["properties"]["model"]["enum"])
                path = os.path.join(tmp, "static", "reporting", "schemas")
                os.makedirs(path)
                with open(os.path.join(path, "query_schema.json"), "w") as f:
                    f.write('{"sample": "json"}')
                r = self.client.get(url)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data, {"sample": "json"})


class TestAssets(AssetRootMixin, ULRMMTestCase):
    def setUp(self):
        super().setUp()
        self.authenticate()

    def write(self, name, content=b"x"):
        path = os.path.join(self.asset_root, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(content)
        return path

    def test_list_folder(self):
        os.makedirs(os.path.join(self.asset_root, "some/valid/path/folder1"))
        self.write("some/valid/path/file1.txt", b"x" * 100)
        r = self.client.get(f"{base_url}/assets/", {"path": "/some/valid/path"})
        self.assertEqual(r.status_code, 200)
        folder, file = r.data
        self.assertEqual(
            (folder["name"], folder["type"], folder["size"], folder["path"]),
            ("folder1", "folder", None, "some/valid/path/folder1"),
        )
        self.assertEqual(
            (file["name"], file["type"], file["size"], file["path"]),
            ("file1.txt", "file", "100", "some/valid/path/file1.txt"),
        )
        self.assertEqual(
            file["url"],
            "https://api.example.com/reporting/assets/some/valid/path/file1.txt",
        )

        r = self.client.get(f"{base_url}/assets/")
        self.assertEqual([e["path"] for e in r.data], ["some"])

        for path in ("some/invalid/path", "../x", "/etc"):
            with self.subTest(path=path):
                r = self.client.get(f"{base_url}/assets/", {"path": path})
                self.assertEqual(r.status_code, 400)

    def test_tree(self):
        sub = self.make_asset("subdir/subdirfile.txt")
        top = self.make_asset("file1.txt")
        self.write("unregistered.txt")
        r = self.client.get(f"{base_url}/assets/all/")
        self.assertEqual(r.status_code, 200)
        (root,) = r.data
        folder_keys = {"selectable": False, "icon": "folder", "iconColor": "yellow-9"}
        self.assertEqual((root["name"], root["path"]), ("Report Assets", ""))
        self.assertLessEqual(folder_keys.items(), root.items())
        subdir, file = root["children"]
        self.assertEqual((subdir["path"], subdir["type"]), ("subdir", "folder"))
        self.assertLessEqual(folder_keys.items(), subdir.items())
        self.assertEqual(
            subdir["children"],
            [
                {
                    "id": str(sub.id),
                    "type": "file",
                    "name": "subdirfile.txt",
                    "path": "subdir/subdirfile.txt",
                    "icon": "description",
                }
            ],
        )
        self.assertEqual((file["id"], file["path"]), (str(top.id), "file1.txt"))

        r = self.client.get(f"{base_url}/assets/all/", {"onlyFolders": "true"})
        self.assertNotIn('"type": "file"', json.dumps(r.data))
        self.assertEqual(r.data[0]["children"][0]["children"], [])

        with override_settings(REPORTING_ASSETS_BASE_PATH="/nonexistent/assets"):
            r = self.client.get(f"{base_url}/assets/all/")
        self.assertEqual(r.status_code, 400)

    def test_rename_file(self):
        asset = self.make_asset("path/to/file.txt")
        url = f"{base_url}/assets/rename/"
        r = self.client.put(
            url, {"path": "path/to/file.txt", "newName": "newname.txt"}, "json"
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data, "path/to/newname.txt")
        self.assertTrue(os.path.isfile(os.path.join(self.asset_root, r.data)))
        asset.refresh_from_db()
        self.assertEqual(asset.file.name, "path/to/newname.txt")

        # taken names get a suffix
        self.write("path/to/taken.txt")
        r = self.client.put(
            url, {"path": "path/to/newname.txt", "newName": "taken.txt"}, "json"
        )
        self.assertTrue(r.data.startswith("path/to/taken_"))
        self.assertNotEqual(r.data, "path/to/taken.txt")

        # unregistered files rename fine
        self.write("loose.txt")
        r = self.client.put(url, {"path": "loose.txt", "newName": "l2.txt"}, "json")
        self.assertEqual(r.status_code, 200)

    def test_rename_folder_updates_rows(self):
        one = self.make_asset("folder/a.png")
        two = self.make_asset("folder/deep/b.png")
        other = self.make_asset("folderx/c.png")
        r = self.client.put(
            f"{base_url}/assets/rename/",
            {"path": "folder", "newName": "renamed"},
            format="json",
        )
        self.assertEqual(r.data, "renamed")
        for asset, name in (
            (one, "renamed/a.png"),
            (two, "renamed/deep/b.png"),
            (other, "folderx/c.png"),
        ):
            asset.refresh_from_db()
            self.assertEqual(asset.file.name, name)
            self.assertTrue(os.path.isfile(os.path.join(self.asset_root, name)))

    def test_rename_refusals(self):
        self.make_asset("a/file.txt")
        url = f"{base_url}/assets/rename/"
        bad = [
            {"path": "../outside/path", "newName": "x"},
            {"path": "/etc/passwd", "newName": "x"},
            {"path": "a/file.txt", "newName": "../../x.txt"},
            {"path": "a/file.txt", "newName": "b/x.txt"},
            {"path": "a/file.txt", "newName": ".."},
            {"path": "missing.txt", "newName": "x"},
            {"path": ".", "newName": "x"},
            {"path": "a/file.txt"},
            {},
        ]
        for data in bad:
            with self.subTest(data=data):
                self.assertEqual(self.client.put(url, data, "json").status_code, 400)
        self.assertTrue(os.path.isfile(os.path.join(self.asset_root, "a/file.txt")))

        with patch("reporting.storage.os.rename", side_effect=OSError("/opt/secret")):
            r = self.client.put(url, {"path": "a/file.txt", "newName": "b.txt"}, "json")
        self.assertEqual(r.status_code, 400)
        self.assertNotIn("/opt", r.data)

    def test_rename_keeps_the_type_allowlist(self):
        asset = self.make_asset("logo.png")
        url = f"{base_url}/assets/rename/"
        for name in ("logo.html", "logo.js", "logo", "logo.png.exe"):
            with self.subTest(name=name):
                r = self.client.put(url, {"path": "logo.png", "newName": name}, "json")
                self.assertEqual(r.status_code, 400)
                self.assertEqual(r.data, f"{name}: this file type is not allowed")
        asset.refresh_from_db()
        self.assertEqual(asset.file.name, "logo.png")
        self.assertTrue(os.path.isfile(os.path.join(self.asset_root, "logo.png")))

        r = self.client.put(url, {"path": "logo.png", "newName": "logo.WEBP"}, "json")
        self.assertEqual(r.data, "logo.WEBP")
        # folders take any single name
        self.make_asset("dir/a.png")
        r = self.client.put(url, {"path": "dir", "newName": "dir.html"}, "json")
        self.assertEqual(r.data, "dir.html")

    def test_rename_rolls_back_when_paths_get_too_long(self):
        asset = self.make_asset("short/a.png")
        r = self.client.put(
            f"{base_url}/assets/rename/",
            {"path": "short", "newName": "x" * 99},
            format="json",
        )
        self.assertEqual(r.status_code, 400)
        asset.refresh_from_db()
        self.assertEqual(asset.file.name, "short/a.png")
        self.assertTrue(os.path.isfile(os.path.join(self.asset_root, "short/a.png")))

    def test_new_folder(self):
        os.makedirs(os.path.join(self.asset_root, "new/path/to"))
        url = f"{base_url}/assets/newfolder/"
        r = self.client.post(url, {"path": "/new/path/to/folder"}, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data, "new/path/to/folder")
        self.assertTrue(os.path.isdir(os.path.join(self.asset_root, r.data)))
        r = self.client.post(url, {"path": "new/path/to/folder"}, format="json")
        self.assertTrue(r.data.startswith("new/path/to/folder_"))

        for data in ({}, {"path": ""}, {"path": "missing/parent"}, {"path": "../x"}):
            with self.subTest(data=data):
                r = self.client.post(url, data, format="json")
                self.assertEqual(r.status_code, 400)
                self.assertNotIn(self.asset_root, str(r.data))

    def test_delete(self):
        one = self.make_asset("path/to/dir/a.txt")
        two = self.make_asset("path/to/dir/b.txt")
        neighbour = self.make_asset("path/to/dirx.txt")
        file = self.make_asset("path/to/file.txt")
        loose = self.write("path/loose.txt")
        url = f"{base_url}/assets/delete/"

        r = self.client.post(url, {"paths": ["path/to/dir"]}, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertFalse(os.path.exists(os.path.join(self.asset_root, "path/to/dir")))
        self.assertFalse(ReportAsset.objects.filter(pk__in=[one.pk, two.pk]).exists())
        self.assertTrue(ReportAsset.objects.filter(pk=neighbour.pk).exists())

        r = self.client.post(
            url, {"paths": ["/path/to/file.txt", "path/loose.txt"]}, format="json"
        )
        self.assertEqual(r.status_code, 200)
        self.assertFalse(ReportAsset.objects.filter(pk=file.pk).exists())
        self.assertFalse(os.path.exists(loose))

    def test_delete_form_encoded(self):
        one = self.make_asset("a.txt")
        self.make_asset("b.txt")
        url = f"{base_url}/assets/delete/"
        r = self.client.post(url, {"paths": ["a.txt", "b.txt"]}, format="multipart")
        self.assertEqual(r.status_code, 200)
        self.assertFalse(ReportAsset.objects.filter(pk=one.pk).exists())
        self.assertEqual(os.listdir(self.asset_root), [])

        r = self.client.post(url, {"other": "x"}, format="multipart")
        self.assertEqual(r.status_code, 400)
        r = self.client.post(url, {"paths": ["../outside"]}, format="multipart")
        self.assertEqual(r.status_code, 400)

    def test_delete_refusals(self):
        self.make_asset("keep.txt")
        url = f"{base_url}/assets/delete/"
        for paths in ([""], ["/"], ["."], ["sub/.."], ["../outside/path"], [1], "x"):
            with self.subTest(paths=paths):
                r = self.client.post(url, {"paths": paths}, format="json")
                self.assertEqual(r.status_code, 400)
        self.assertTrue(os.path.isfile(os.path.join(self.asset_root, "keep.txt")))

        os.makedirs(os.path.join(self.asset_root, "dir"))
        with patch("reporting.storage.shutil.rmtree", side_effect=OSError("/opt/x")):
            r = self.client.post(url, {"paths": ["dir"]}, format="json")
        self.assertEqual(r.status_code, 400)
        self.assertNotIn("/opt", r.data)

    def test_upload(self):
        os.makedirs(os.path.join(self.asset_root, "path"))
        url = f"{base_url}/assets/upload/"

        def upload(**extra):
            files = {
                "test123.txt": SimpleUploadedFile("test123.txt", b"content"),
                **extra,
            }
            return self.client.post(
                url, {"parentPath": "path", **files}, format="multipart"
            )

        r = upload()
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data["test123.txt"]["filename"], "path/test123.txt")
        self.assertTrue(
            ReportAsset.objects.filter(
                id=r.data["test123.txt"]["id"], file="path/test123.txt"
            ).exists()
        )
        r = upload()
        self.assertNotEqual(r.data["test123.txt"]["filename"], "path/test123.txt")
        self.assertTrue(r.data["test123.txt"]["filename"].startswith("path/test123_"))

    def test_upload_refusals(self):
        self.write("afile.txt")
        url = f"{base_url}/assets/upload/"
        file = SimpleUploadedFile("a.txt", b"x")
        r = self.client.post(url, {"parentPath": "afile.txt", "a.txt": file})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.data, "parentPath doesn't point to a directory")
        r = self.client.post(url, {"parentPath": "../path", "a.txt": file})
        self.assertEqual(r.status_code, 400)

        for name in ("evil.html", "noext", "../a.png", "sub/a.png"):
            with self.subTest(name=name):
                r = self.client.post(url, {name: SimpleUploadedFile("f", b"x")})
                self.assertEqual(r.status_code, 400)

        with override_settings(REPORTING_MAX_ASSET_MB=0):
            r = self.client.post(url, {"big.png": SimpleUploadedFile("f", b"x")})
        self.assertEqual(r.status_code, 400)
        self.assertFalse(ReportAsset.objects.exists())
        self.assertEqual(os.listdir(self.asset_root), ["afile.txt"])

    def test_download(self):
        self.write("folder/one.txt", b"1")
        self.write("folder/sub/two.txt", b"2")
        os.makedirs(os.path.join(self.asset_root, "folder/empty"))
        url = f"{base_url}/assets/download/"

        r = self.client.get(url, {"path": "folder/one.txt"})
        self.assertEqual(r.status_code, 200)
        self.assertIn('attachment; filename="one.txt"', r["Content-Disposition"])
        self.assertEqual(b"".join(r.streaming_content), b"1")

        r = self.client.get(url, {"path": "folder"})
        self.assertEqual(r.status_code, 200)
        self.assertIn('filename="folder.zip"', r["Content-Disposition"])
        archive = zipfile.ZipFile(io.BytesIO(b"".join(r.streaming_content)))
        self.assertEqual(
            sorted(archive.namelist()), ["empty/", "one.txt", "sub/", "sub/two.txt"]
        )
        leftovers = [
            name
            for _, _, files in os.walk(self.asset_root)
            for name in files
            if name.endswith(".zip")
        ]
        self.assertEqual(leftovers, [])

        for path in ("missing.txt", "../etc/passwd", "/etc/passwd"):
            with self.subTest(path=path):
                r = self.client.get(url, {"path": path})
                self.assertEqual(r.status_code, 400)

    def test_download_skips_links(self):
        self.write("folder/real.txt")
        os.symlink("/etc/hostname", os.path.join(self.asset_root, "folder/link.txt"))
        r = self.client.get(f"{base_url}/assets/download/", {"path": "folder"})
        archive = zipfile.ZipFile(io.BytesIO(b"".join(r.streaming_content)))
        self.assertEqual(archive.namelist(), ["real.txt"])
        r = self.client.get(f"{base_url}/assets/download/", {"path": "folder/link.txt"})
        self.assertEqual(r.status_code, 400)

    def test_serve(self):
        self.client.logout()
        asset = self.make_asset("test_asset.png")
        url = f"{base_url}/assets/test_asset.png"
        r = self.client.get(url, {"id": str(asset.id)})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r["X-Accel-Redirect"], "/assets/test_asset.png")
        self.assertEqual(r["Content-Type"], "image/png")
        self.assertEqual(r["X-Content-Type-Options"], "nosniff")
        self.assertFalse(r.has_header("Content-Disposition"))

        r = self.client.get(f"{base_url}/assets/wrong_path.txt", {"id": asset.id})
        self.assertEqual(r.status_code, 403)
        r = self.client.get(url, {"id": str(uuid.uuid4())})
        self.assertEqual(r.status_code, 404)
        for params in ({"id": "invalid_uuid"}, {}):
            with self.subTest(params=params):
                r = self.client.get(url, params)
                self.assertEqual(r.status_code, 400)
                self.assertEqual(r.data, "There was an error processing the request")
        # any spelling uuid.UUID reads
        for spelling in (
            asset.id.hex,
            f"{{{asset.id}}}",
            asset.id.urn,
            str(asset.id).upper(),
        ):
            with self.subTest(spelling=spelling):
                r = self.client.get(url, {"id": spelling})
                self.assertEqual(r.status_code, 200)

        # a bad token does not matter on this route
        self.client.credentials(HTTP_AUTHORIZATION="Token nonsense")
        r = self.client.get(url, {"id": str(asset.id)})
        self.assertEqual(r.status_code, 200)

    def test_serve_active_content_safely(self):
        for name in ("logo.svg", "doc.pdf", "style.css", "legacy.html", "dir/a b?.txt"):
            with self.subTest(name=name):
                asset = self.make_asset(name)
                r = self.client.get(
                    f"{base_url}/assets/{name.replace('?', '%3F')}",
                    {"id": str(asset.id)},
                )
                self.assertEqual(r.status_code, 200)
                self.assertTrue(r["Content-Disposition"].startswith("attachment"))
                self.assertEqual(r["Content-Security-Policy"], "sandbox")
                self.assertEqual(r["X-Content-Type-Options"], "nosniff")
        self.assertEqual(r["X-Accel-Redirect"], "/assets/dir/a%20b%3F.txt")


class TestSchedules(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.template = baker.make(
            "reporting.ReportTemplate", name="T", template_md="x", type="html"
        )
        self.core_schedule = baker.make("core.Schedule", name="Every day")
        self.url = f"{base_url}/schedules/"

    def make_schedule(self, **kwargs):
        return baker.make(
            "reporting.ReportSchedule",
            report_template=self.template,
            schedule=self.core_schedule,
            dependencies={},
            **kwargs,
        )

    def test_list(self):
        for _ in range(3):
            self.make_schedule()
        r = self.client.get(self.url)
        self.assertEqual(len(r.data), 3)
        self.assertEqual(r.data[0]["report_template_name"], "T")
        self.assertEqual(r.data[0]["schedule_name"], "Every day")
        self.assertIsNone(r.data[0]["owner_name"])
        self.assertNotIn("locked_at", r.data[0])
        self.assertNotIn("created_by", r.data[0])

    def test_create(self):
        data = {
            "name": "Monthly Sales Report",
            "report_template": self.template.pk,
            "schedule": self.core_schedule.pk,
            "format": "pdf",
            "send_report_email": True,
            "last_run": "2020-01-01T00:00:00Z",
        }
        r = self.client.post(self.url, data, format="json")
        self.assertEqual(r.status_code, 200)
        schedule = ReportSchedule.objects.get()
        self.assertEqual(schedule.name, "Monthly Sales Report")
        self.assertTrue(schedule.enabled)
        self.assertEqual(schedule.dependencies, {})
        self.assertEqual(schedule.email_recipients, [])
        self.assertEqual(schedule.email_settings, {})
        self.assertIsNone(schedule.last_run)
        self.assertEqual(schedule.owner, self.john)
        self.assertEqual(r.data["owner_name"], "john")

        bad = [
            {"email_recipients": ["invalid"]},
            {"schedule": None},
            {"email_settings": {"subject": "a\nb"}},
            {"email_settings": {"attachment_extension": "csv\n"}},
            {"dependencies": [1]},
            {"format": "docx"},
            {"timezone": "Not/AZone"},
        ]
        for change in bad:
            with self.subTest(change=change):
                r = self.client.post(self.url, {**data, **change}, format="json")
                self.assertEqual(r.status_code, 400)
        del data["schedule"]
        self.assertEqual(self.client.post(self.url, data, "json").status_code, 400)

    def test_detail_and_owner_follows_editor(self):
        schedule = self.make_schedule(name="old")
        url = f"{self.url}{schedule.pk}/"
        r = self.client.get(url)
        self.assertEqual(r.data["id"], schedule.pk)

        editor = self.create_user_with_roles(["can_manage_reports"])
        self.client.force_authenticate(user=editor)
        r = self.client.put(url, {"name": "new"}, format="json")
        self.assertEqual(r.status_code, 200)
        schedule.refresh_from_db()
        self.assertEqual(schedule.name, "new")
        self.assertEqual(schedule.owner, editor)

        self.assertEqual(self.client.delete(url).status_code, 200)
        self.assertFalse(ReportSchedule.objects.exists())
        self.assertEqual(self.client.get(url).status_code, 404)

    def test_dependencies_are_checked_against_the_editor(self):
        own = baker.make("clients.Client")
        foreign = baker.make("clients.Client")
        limited = self.create_user_with_roles(["can_manage_reports"])
        limited.role.can_view_clients.set([own])
        self.client.force_authenticate(user=limited)
        data = {
            "name": "s",
            "report_template": self.template.pk,
            "schedule": self.core_schedule.pk,
        }
        for dependencies in (
            {"client": foreign.pk},
            {"client": "abc"},
            {"agent": "missing"},
            {"data_sources": 1},
        ):
            with self.subTest(dependencies=dependencies):
                r = self.client.post(
                    self.url, {**data, "dependencies": dependencies}, format="json"
                )
                self.assertEqual(r.status_code, 400)
                self.assertIn("dependencies", r.data)
        self.assertFalse(ReportSchedule.objects.exists())
        r = self.client.post(
            self.url, {**data, "dependencies": {"client": own.pk}}, format="json"
        )
        self.assertEqual(r.status_code, 200)

        # saving makes the editor the owner, so stored dependencies count too
        stored = self.make_schedule(owner=self.john)
        stored.dependencies = {"client": foreign.pk}
        stored.save()
        url = f"{self.url}{stored.pk}/"
        r = self.client.put(url, {"enabled": True}, format="json")
        self.assertEqual(r.status_code, 400)
        stored.refresh_from_db()
        self.assertEqual(stored.owner, self.john)
        r = self.client.put(url, {"dependencies": {"client": own.pk}}, format="json")
        self.assertEqual(r.status_code, 200)

        self.client.force_authenticate(user=self.john)
        r = self.client.put(url, {"dependencies": {"client": foreign.pk}}, "json")
        self.assertEqual(r.status_code, 200)

    @patch("reporting.tasks.email_report.delay")
    def test_run_now_records_user_and_schedule(self, delay):
        schedule = self.make_schedule()
        r = self.client.post(f"{self.url}{schedule.pk}/run/")
        self.assertEqual(r.status_code, 200)
        history = ReportHistory.objects.get()
        self.assertEqual(
            (history.user, history.schedule, history.run_by),
            (self.john, schedule, "john"),
        )
        delay.assert_called_once()

    def test_deleting_the_owner_keeps_the_schedule_running(self):
        self.setup_coresettings()
        owner = self.create_user_with_roles(["can_manage_reports"])
        schedule = self.make_schedule(owner=owner, enabled=True)
        owner_pk = owner.pk
        owner.delete()
        schedule.refresh_from_db()
        self.assertIsNone(schedule.owner)
        self.assertTrue(schedule.enabled)
        audit = AuditLog.objects.get(object_type="reportschedule")
        self.assertEqual(audit.before_value["owner"], owner_pk)
        self.assertIsNone(audit.after_value["owner"])
        self.assertTrue(
            DebugLog.objects.filter(message__contains=owner.username).exists()
        )

    def test_run_now(self):
        schedule = self.make_schedule()
        url = f"{self.url}{schedule.pk}/run/"
        with patch(
            "reporting.views.run_scheduled_report", return_value=(None, None)
        ) as run:
            r = self.client.post(url)
        self.assertEqual(r.status_code, 200)
        run.assert_called_once_with(schedule=schedule, user=self.john)

        with patch(
            "reporting.views.run_scheduled_report",
            return_value=(None, "Something went wrong"),
        ):
            r = self.client.post(url)
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.data, "Something went wrong")

    def test_audit(self):
        schedule = self.make_schedule(name="before", owner=self.john)
        AuditLog.objects.all().delete()
        self.client.put(f"{self.url}{schedule.pk}/", {"name": "after"}, format="json")
        entry = AuditLog.objects.get(object_type="reportschedule")
        self.assertEqual(entry.action, "modify")
        fields = {
            "name",
            "enabled",
            "report_template",
            "format",
            "schedule",
            "email_recipients",
            "send_report_email",
            "email_settings",
            "timezone",
        }
        self.assertLessEqual(fields, set(entry.before_value))
        self.assertLessEqual(fields, set(entry.after_value))
        self.assertEqual(entry.after_value["name"], "after")

    def test_timezone(self):
        schedule = self.make_schedule(owner=self.john)
        url = f"{self.url}{schedule.pk}/"
        r = self.client.put(url, {"timezone": "Europe/Berlin"}, format="json")
        self.assertEqual(r.status_code, 200)
        r = self.client.put(url, {"timezone": "Mars/Base"}, format="json")
        self.assertEqual(r.status_code, 400)
        self.assertIn("timezone", r.data)
        schedule.refresh_from_db()
        self.assertEqual(schedule.timezone, "Europe/Berlin")
        r = self.client.put(url, {"timezone": None}, format="json")
        self.assertEqual(r.status_code, 200)
        schedule.refresh_from_db()
        self.assertIsNone(schedule.timezone)

    def test_core_schedule_in_use(self):
        self.make_schedule()
        # outside of tests the deferred constraint fires when delete() commits
        with connection.cursor() as cursor:
            cursor.execute("SET CONSTRAINTS ALL IMMEDIATE")
        r = self.client.delete(f"/core/schedules/{self.core_schedule.pk}/")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.data, "This schedule is currently in use.")


class TestHistory(AssetRootMixin, ULRMMTestCase):
    def setUp(self):
        super().setUp()
        self.authenticate()
        self.template = baker.make(
            "reporting.ReportTemplate", name="Hist", template_md="x"
        )
        self.url = f"{base_url}/history/"

    def test_list_and_delete(self):
        rows = baker.make(
            "reporting.ReportHistory", report_template=self.template, _quantity=5
        )
        r = self.client.get(self.url)
        self.assertEqual(len(r.data), 5)
        self.assertNotIn("report_data", r.data[0])
        self.assertEqual(r.data[0]["report_template_name"], "Hist")
        r = self.client.delete(f"{self.url}{rows[0].pk}/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(ReportHistory.objects.count(), 4)

    def test_rerender(self):
        history = baker.make(
            "reporting.ReportHistory", report_template=self.template, report_data="<p>"
        )
        url = f"{self.url}{history.pk}/run/"
        with patch(
            "reporting.views.normalize_asset_url", return_value="<html></html>"
        ) as normalize, patch(
            "reporting.views.generate_pdf", return_value=b"pdf_content"
        ) as pdf:
            r = self.client.post(url, {"format": "pdf"}, format="json")
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r["Content-Type"], "application/pdf")
            self.assertEqual(r.content, b"pdf_content")
            normalize.assert_called_with("<p>", "pdf")
            pdf.assert_called_with("<html></html>")

            r = self.client.post(url, {"format": "html"}, format="json")
            self.assertEqual(r.data, "<html></html>")
            normalize.assert_called_with("<p>", "html")

        r = self.client.post(url, {"format": "invalid"}, format="json")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.data, "Report format is incorrect.")

    def test_history_is_scoped(self):
        bob = self.create_user_with_roles(["can_manage_reports"])
        other = self.create_user_with_roles(["can_manage_reports"])

        def schedule(owner):
            return baker.make(
                "reporting.ReportSchedule",
                report_template=self.template,
                schedule=baker.make("core.Schedule"),
                owner=owner,
                dependencies={},
            )

        def row(**kwargs):
            return baker.make(
                "reporting.ReportHistory", report_template=self.template, **kwargs
            )

        owned, unowned = schedule(bob), schedule(None)
        mine = row(user=bob, run_by=bob.username)
        # run now by someone else on a schedule bob owns
        on_owned = row(user=self.john, run_by="john", schedule=owned)
        legacy = row(run_by=bob.username)
        system = row(run_by="system", schedule=unowned)
        others = row(user=other, run_by=other.username)

        def visible(user):
            self.client.force_authenticate(user=user)
            return sorted(r["id"] for r in self.client.get(self.url).data)

        self.assertEqual(visible(bob), sorted([mine.pk, on_owned.pk]))
        for hidden in (legacy, system, others):
            with self.subTest(row=hidden.run_by):
                url = f"{self.url}{hidden.pk}/"
                r = self.client.post(f"{url}run/", {"format": "html"}, "json")
                self.assertEqual(r.status_code, 404)
                self.assertEqual(self.client.delete(url).status_code, 404)
        r = self.client.post(f"{self.url}{mine.pk}/run/", {"format": "html"}, "json")
        self.assertEqual(r.status_code, 200)

        # names decide nothing: not "system", not a reused username
        other.username = "system"
        other.save()
        self.assertEqual(visible(other), [others.pk])
        name = bob.username
        bob.delete()
        successor = self.create_user_with_roles(["can_manage_reports"])
        successor.username = name
        successor.save()
        self.assertEqual(visible(successor), [])

        role_superuser = self.create_user_with_roles(["is_superuser"])
        self.assertEqual(len(visible(role_superuser)), 5)

    def test_migration_links_legacy_rows_to_their_runner(self):
        bob = self.create_user_with_roles(["can_manage_reports"])
        bob.username = "legacy-runner"
        bob.save()
        named_system = self.create_user_with_roles(["can_manage_reports"])
        named_system.username = "system"
        named_system.save()

        def row(**kwargs):
            return baker.make(
                "reporting.ReportHistory", report_template=self.template, **kwargs
            )

        legacy = row(run_by=bob.username)
        system = row(run_by="system")
        unknown = row(run_by="deleted-user")
        other_case = row(run_by="Legacy-Runner")
        linked = row(run_by=bob.username, user=self.john)

        migration = import_module("reporting.migrations.0004_link_history_users")
        migration.link_history_users(apps, None)

        users = dict(ReportHistory.objects.values_list("pk", "user_id"))
        self.assertEqual(users[legacy.pk], bob.pk)
        self.assertIsNone(users[system.pk])
        self.assertIsNone(users[unknown.pk])
        self.assertIsNone(users[other_case.pk])
        self.assertEqual(users[linked.pk], self.john.pk)

        self.client.force_authenticate(user=bob)
        self.assertEqual([r["id"] for r in self.client.get(self.url).data], [legacy.pk])
        r = self.client.post(f"{self.url}{legacy.pk}/run/", {"format": "html"}, "json")
        self.assertEqual(r.status_code, 200)

    def test_a_new_owner_does_not_see_earlier_runs(self):
        limited = self.create_user_with_roles(["can_manage_reports"])
        schedule = baker.make(
            "reporting.ReportSchedule",
            report_template=self.template,
            schedule=baker.make("core.Schedule"),
            dependencies={},
        )
        url = f"{base_url}/schedules/{schedule.pk}/"
        unscoped = baker.make(
            "reporting.ReportHistory", report_template=self.template, schedule=schedule
        )
        self.client.force_authenticate(user=limited)
        self.assertEqual(self.client.put(url, {"name": "a"}, "json").status_code, 200)
        self.assertEqual(self.client.get(self.url).data, [])

        later = baker.make(
            "reporting.ReportHistory",
            report_template=self.template,
            schedule=schedule,
            user=self.john,
        )
        # saving again as the same owner keeps the rows
        self.assertEqual(self.client.put(url, {"name": "b"}, "json").status_code, 200)
        self.assertEqual([r["id"] for r in self.client.get(self.url).data], [later.pk])
        self.client.force_authenticate(user=self.john)
        self.assertEqual(len(self.client.get(self.url).data), 2)
        unscoped.refresh_from_db()
        self.assertIsNone(unscoped.schedule)


class TestDashinfoFlags(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.authenticate()

    def test_reporting_flags(self):
        cases = (
            (self.create_user_with_roles([]), False, False),
            (self.create_user_with_roles(["can_view_reports"]), True, False),
            (self.create_user_with_roles(["can_manage_reports"]), True, True),
            (self.create_user_with_roles(["is_superuser"]), True, True),
            (baker.make("accounts.User", is_superuser=True, role=None), True, True),
            (baker.make("accounts.User", role=None), False, False),
        )
        for user, view, manage in cases:
            with self.subTest(view=view, manage=manage):
                self.client.force_authenticate(user=user)
                r = self.client.get("/core/dashinfo/")
                self.assertEqual(r.status_code, 200)
                self.assertIs(r.data["can_view_reports"], view)
                self.assertIs(r.data["can_manage_reports"], manage)


@override_settings(CACHES=LOCMEM_CACHE)
class TestReportFrame(ULRMMTestCase):
    def setUp(self):
        self.setup_client()
        self.client.force_authenticate(
            user=self.create_user_with_roles(["can_view_reports"])
        )

    def post(self, html="<p>hi</p>", format="html"):
        return self.client.post(
            f"{base_url}/frame/", {"html": html, "format": format}, format="json"
        )

    def test_frame_is_served_once_with_its_policy(self):
        r = self.post("<script>x()</script>")
        self.assertEqual(r.status_code, 200)
        url = r.data["url"]
        prefix = "https://api.example.com/reporting/frame/"
        self.assertTrue(url.startswith(prefix), url)
        path = url.removeprefix("https://api.example.com")
        self.client.logout()
        r = self.client.get(path)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.content, b"<script>x()</script>")
        self.assertEqual(r["Content-Type"], "text/html; charset=utf-8")
        csp = r["Content-Security-Policy"]
        self.assertTrue(csp.startswith("default-src 'none'; script-src "), csp)
        self.assertIn("connect-src 'none'; form-action 'none'", csp)
        self.assertTrue(csp.endswith("; frame-ancestors https://rmm.example.com"))
        self.assertIn("https://api.example.com/static/reporting/js/; style-src", csp)
        self.assertEqual(r["X-Content-Type-Options"], "nosniff")
        self.assertEqual(r["Referrer-Policy"], "no-referrer")
        self.assertEqual(r["Cache-Control"], "no-store")
        self.assertNotIn("X-Frame-Options", r)
        self.assertEqual(self.client.get(path).status_code, 404)

    def test_bad_requests(self):
        self.assertEqual(self.post(format="pdf").status_code, 400)
        self.assertEqual(self.post(html=["x"]).status_code, 400)
        self.assertEqual(self.post(html="x" * (FRAME_MAX + 1)).status_code, 400)
        self.assertEqual(self.post(html="x" * FRAME_MAX).status_code, 200)
        r = self.client.post(f"{base_url}/frame/", ["x"], format="json")
        self.assertEqual(r.status_code, 400)
        # a declared length above the cap is refused before the body is read
        r = self.client.post(
            f"{base_url}/frame/",
            {"html": "x", "format": "html"},
            format="json",
            CONTENT_LENGTH=str(2 * FRAME_MAX + 1),
        )
        self.assertEqual(r.status_code, 400)

    def test_unknown_or_malformed_token(self):
        path = self.post().data["url"].removeprefix("https://api.example.com")
        self.client.logout()
        self.assertEqual(self.client.post(path).status_code, 405)
        for bad in ("a" * 43, "a.b"):
            r = self.client.get(f"{base_url}/frame/{bad}/")
            self.assertEqual(r.status_code, 404)
        self.assertEqual(self.client.get(path).status_code, 200)

    def test_view_role_needed(self):
        self.client.force_authenticate(user=baker.make("accounts.User"))
        self.assertEqual(self.post().status_code, 403)
