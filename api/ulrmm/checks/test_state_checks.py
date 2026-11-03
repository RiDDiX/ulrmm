# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.utils import timezone as djangotime
from model_bakery import baker
from rest_framework.exceptions import ValidationError

from automation.models import Policy, _check_key
from checks.models import Check, CheckResult, clean_result
from metrics.models import AgentState
from ulrmm.constants import (
    POLICY_CHECK_FIELDS_TO_COPY,
    AgentPlat,
    AlertSeverity,
    CheckStatus,
    CheckType,
)
from ulrmm.test import ULRMMTestCase


class TestStateCheckValidation(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        self.linux = baker.make_recipe("agents.online_agent", plat=AgentPlat.LINUX)
        self.windows = baker.make_recipe("agents.online_agent")

    def add(self, agent=None, **data):
        data.setdefault("agent", (agent or self.linux).agent_id)
        return self.client.post("/checks/", data, format="json")

    def test_systemd(self):
        r = self.add(check_type=CheckType.SYSTEMD, svc_name="nginx")
        self.assertEqual(r.status_code, 200, r.data)
        self.assertEqual(
            r.data,
            "Systemd Unit Check: nginx.service was added! Agent update required before it runs.",
        )
        check = Check.objects.get(check_type=CheckType.SYSTEMD)
        self.assertEqual(check.svc_name, "nginx.service")

        AgentState.objects.create(agent=self.linux, received=djangotime.now())
        r = self.add(check_type=CheckType.SYSTEMD, svc_name="getty@tty1.service")
        self.assertEqual(r.data, "Systemd Unit Check: getty@tty1.service was added!")
        r = self.add(check_type=CheckType.SYSTEMD, svc_name="backup.timer")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(Check.objects.filter(svc_name="backup.timer").exists())

        for bad in ("", "-x", "a b", "a;b", "x" * 256, None):
            r = self.add(check_type=CheckType.SYSTEMD, svc_name=bad)
            self.assertEqual(r.status_code, 400, bad)
        rule = (
            "Unit names may contain letters, digits and @ . _ : - "
            "and must not start with -"
        )
        for bad, message in (
            ("", "Enter a systemd unit."),
            ("-x", rule),
            ("a b", rule),
            ("x" * 250, "Unit name too long."),
        ):
            r = self.add(check_type=CheckType.SYSTEMD, svc_name=bad)
            self.assertEqual(r.data["svc_name"], [message], bad)
        r = self.add(check_type=CheckType.SYSTEMD, svc_name="nginx.service")
        self.assertEqual(r.status_code, 400)
        r = self.add(self.windows, check_type=CheckType.SYSTEMD, svc_name="nginx")
        self.assertEqual(r.status_code, 400)

        # edits keep the rules
        check = Check.objects.get(svc_name="nginx.service")
        r = self.client.put(f"/checks/{check.pk}/", {"svc_name": "sshd"}, format="json")
        self.assertEqual(r.status_code, 200)
        check.refresh_from_db()
        self.assertEqual(check.svc_name, "sshd.service")
        r = self.client.put(f"/checks/{check.pk}/", {"svc_name": "-rf"}, format="json")
        self.assertEqual(r.status_code, 400)

    def test_container(self):
        r = self.add(check_type=CheckType.CONTAINER, container="web")
        self.assertEqual(r.status_code, 200, r.data)
        self.assertIn("Container Check: web was added!", r.data)
        r = self.add(
            self.windows,
            check_type=CheckType.CONTAINER,
            container="ab12cd34ef56",
            container_kind="hyperv",
        )
        self.assertEqual(r.status_code, 200, r.data)
        r = self.add(
            check_type=CheckType.CONTAINER, container="web", container_kind="docker"
        )
        self.assertEqual(r.status_code, 200)
        r = self.add(check_type=CheckType.CONTAINER, container="web")
        self.assertEqual(r.status_code, 400)
        r = self.add(
            check_type=CheckType.CONTAINER,
            container="registry/app:1",
            container_kind="pve-lxc",
        )
        self.assertEqual(r.status_code, 200)
        for bad in ("", "-x", "a b", "a$b"):
            r = self.add(check_type=CheckType.CONTAINER, container=bad)
            self.assertEqual(r.status_code, 400, bad)
        r = self.add(
            check_type=CheckType.CONTAINER, container="db", container_kind="vmware"
        )
        self.assertEqual(r.status_code, 400)

    def test_metric(self):
        r = self.add(
            check_type=CheckType.METRIC,
            metric="net.rx_bps",
            metric_labels={"if": "eth0"},
            metric_warning=1e6,
            metric_error=5e6,
            metric_samples=3,
        )
        self.assertEqual(r.status_code, 200, r.data)
        self.assertIn(
            "Metric Threshold Check: net.rx_bps{if=eth0} above 1e+06/5e+06", r.data
        )
        r = self.add(
            check_type=CheckType.METRIC,
            metric="disk.used_pct",
            metric_labels={"mount": "*"},
            metric_op="below",
            metric_warning=20,
        )
        self.assertEqual(r.status_code, 200, r.data)
        self.assertIn("disk.used_pct{mount=*} below 20/-", r.data)
        r = self.add(
            check_type=CheckType.METRIC,
            metric="time.offset_ms",
            metric_error=-50,
            metric_op="below",
        )
        self.assertEqual(r.status_code, 200, r.data)

        bad = (
            {"metric": "nope", "metric_error": 1},
            {"metric": None, "metric_error": 1},
            {"metric": "cpu.pct"},
            {"metric": "cpu.pct", "metric_labels": {"if": "eth0"}, "metric_error": 1},
            {
                "metric": "net.rx_bps",
                "metric_labels": {"if": "x" * 65},
                "metric_error": 1,
            },
            {"metric": "net.rx_bps", "metric_labels": {"if": ""}, "metric_error": 1},
            {"metric": "net.rx_bps", "metric_labels": {"if": 5}, "metric_error": 1},
            {"metric": "net.rx_bps", "metric_labels": ["eth0"], "metric_error": 1},
            {"metric": "net.rx_bps", "metric_labels": {}, "metric_error": 1},
            {
                "metric": "ctr.cpu_pct",
                "metric_labels": {"name": "web"},
                "metric_error": 1,
            },
            {"metric": "cpu.pct", "metric_warning": 90, "metric_error": 80},
            {
                "metric": "cpu.pct",
                "metric_op": "below",
                "metric_warning": 10,
                "metric_error": 20,
            },
            {"metric": "cpu.pct", "metric_error": 1, "metric_samples": 0},
            {"metric": "cpu.pct", "metric_error": 1, "metric_samples": 61},
            {"metric": "cpu.pct", "metric_error": 1, "metric_op": "equal"},
            # already exists
            {
                "metric": "net.rx_bps",
                "metric_labels": {"if": "eth0"},
                "metric_error": 9,
            },
        )
        for data in bad:
            r = self.add(check_type=CheckType.METRIC, **data)
            self.assertEqual(r.status_code, 400, data)

        # every label key of the metric is required, * stands for any value
        r = self.add(
            check_type=CheckType.METRIC,
            metric="net.rx_bps",
            metric_labels={},
            metric_error=1,
        )
        self.assertEqual(r.data["metric_labels"], ["Missing label if, use * for any."])

        # a policy check may use the same series
        policy = baker.make("automation.Policy")

        def add_policy(labels):
            return self.client.post(
                "/checks/",
                {
                    "policy": policy.pk,
                    "check_type": CheckType.METRIC,
                    "metric": "net.rx_bps",
                    "metric_labels": labels,
                    "metric_error": 9,
                },
                format="json",
            )

        r = add_policy({"if": "eth0"})
        self.assertEqual(r.status_code, 200, r.data)
        r = add_policy({"if": "*"})
        self.assertEqual(r.status_code, 200, r.data)
        r = add_policy({})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.data["metric_labels"], ["Missing label if, use * for any."])

    def test_new_fields_in_payload_and_copy_list(self):
        check = baker.make(
            "checks.Check",
            agent=self.linux,
            check_type=CheckType.METRIC,
            metric="cpu.pct",
            metric_error=90,
        )
        r = self.client.get(f"/checks/{check.pk}/")
        for field, value in (
            ("container", None),
            ("container_kind", ""),
            ("metric", "cpu.pct"),
            ("metric_labels", {}),
            ("metric_op", "above"),
            ("metric_warning", None),
            ("metric_error", 90.0),
            ("metric_samples", 1),
        ):
            self.assertEqual(r.data[field], value, field)
            self.assertIn(field, POLICY_CHECK_FIELDS_TO_COPY)

    def test_result_cleaning(self):
        for kind in (CheckType.SYSTEMD, CheckType.CONTAINER):
            self.assertEqual(
                clean_result(kind, {"status": "failing", "more_info": "x" * 5000}),
                {"status": "failing", "more_info": "x" * 4096},
            )
            with self.assertRaises(ValidationError):
                clean_result(kind, {"status": "broken"})
        with self.assertRaises(ValidationError):
            clean_result(CheckType.METRIC, {"value": 1})


class TestStateCheckPolicies(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()

    def test_check_keys(self):
        linux = baker.make_recipe("agents.agent", plat=AgentPlat.LINUX)
        windows = baker.make_recipe("agents.agent")
        systemd = Check(check_type=CheckType.SYSTEMD, svc_name="nginx.service")
        container = Check(
            check_type=CheckType.CONTAINER, container="web", container_kind="docker"
        )
        metric = Check(
            check_type=CheckType.METRIC,
            metric="ctr.cpu_pct",
            metric_labels={"name": "web", "kind": "docker"},
        )
        self.assertEqual(_check_key(systemd, linux), ("systemd", "nginx.service"))
        self.assertIsNone(_check_key(systemd, windows))
        self.assertEqual(
            _check_key(container, windows), ("container", ("docker", "web"))
        )
        self.assertEqual(
            _check_key(metric, linux),
            ("metric", ("ctr.cpu_pct", (("kind", "docker"), ("name", "web")))),
        )

    def test_policy_merge_and_override(self):
        policy = baker.make("automation.Policy", active=True)
        linux = baker.make_recipe("agents.agent", plat=AgentPlat.LINUX, policy=policy)
        windows = baker.make_recipe("agents.agent", policy=policy)

        def make(owner, **fields):
            return baker.make("checks.Check", **owner, **fields)

        p_unit = make(
            {"policy": policy}, check_type=CheckType.SYSTEMD, svc_name="a.service"
        )
        p_ctr = make(
            {"policy": policy}, check_type=CheckType.CONTAINER, container="web"
        )
        p_metric = make(
            {"policy": policy},
            check_type=CheckType.METRIC,
            metric="temp.c",
            metric_labels={"sensor": "*"},
            metric_error=90,
        )
        # the agent's own check with the same identity wins over a normal policy
        own = make(
            {"agent": linux},
            check_type=CheckType.METRIC,
            metric="temp.c",
            metric_labels={"sensor": "*"},
            metric_error=70,
        )
        other_labels = make(
            {"agent": linux},
            check_type=CheckType.METRIC,
            metric="temp.c",
            metric_labels={"sensor": "cpu"},
            metric_error=70,
        )

        merged = Policy.get_policy_checks(linux)
        self.assertEqual({c.pk for c in merged}, {p_unit.pk, p_ctr.pk})
        own.refresh_from_db()
        other_labels.refresh_from_db()
        self.assertFalse(own.overridden_by_policy)

        # windows agents do not get the systemd check
        merged = Policy.get_policy_checks(windows)
        self.assertEqual({c.pk for c in merged}, {p_ctr.pk, p_metric.pk})

        policy.enforced = True
        policy.save()
        merged = Policy.get_policy_checks(linux)
        self.assertEqual({c.pk for c in merged}, {p_unit.pk, p_ctr.pk, p_metric.pk})
        own.refresh_from_db()
        self.assertTrue(own.overridden_by_policy)
        other_labels.refresh_from_db()
        self.assertFalse(other_labels.overridden_by_policy)

    def test_policy_copy(self):
        source = baker.make("automation.Policy")
        target = baker.make("automation.Policy")
        check = baker.make(
            "checks.Check",
            policy=source,
            check_type=CheckType.METRIC,
            metric="vm.running",
            metric_labels={"kind": "pve-qemu"},
            metric_op="below",
            metric_warning=3,
            metric_error=1,
            metric_samples=5,
            container="x",
            container_kind="docker",
        )
        check.create_policy_check(target)
        copy = Check.objects.get(policy=target)
        for field in POLICY_CHECK_FIELDS_TO_COPY:
            self.assertEqual(getattr(copy, field), getattr(check, field), field)


class TestStateCheckRunner(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.setup_client()
        self.agent = baker.make_recipe(
            "agents.online_agent", plat=AgentPlat.LINUX, check_interval=120
        )
        self.authenticate_agent(self.agent)

    def make(self, **fields):
        return baker.make(
            "checks.Check", agent=self.agent, dashboard_alert=True, **fields
        )

    def test_runner_leaves_out_metric_checks(self):
        unit = self.make(check_type=CheckType.SYSTEMD, svc_name="nginx.service")
        ctr = self.make(
            check_type=CheckType.CONTAINER, container="web", container_kind="docker"
        )
        self.make(
            check_type=CheckType.METRIC,
            metric="cpu.pct",
            metric_error=1,
            run_interval=30,
        )
        for url in (
            f"/api/v3/{self.agent.agent_id}/checkrunner/",
            f"/api/v3/{self.agent.agent_id}/runchecks/",
        ):
            r = self.client.get(url)
            self.assertEqual(r.status_code, 200)
            self.assertEqual({c["id"] for c in r.data["checks"]}, {unit.pk, ctr.pk})
            sent = {c["id"]: c for c in r.data["checks"]}[ctr.pk]
            self.assertEqual(
                (sent["container"], sent["container_kind"]), ("web", "docker")
            )
            self.assertNotIn("metric", sent)
        # a 30 s metric check does not speed up the agent's runner
        self.assertGreaterEqual(self.agent.check_run_interval(), 120)

        # an agent cannot post a metric result
        metric = Check.objects.get(check_type=CheckType.METRIC)
        r = self.client.patch(
            "/api/v3/checkrunner/",
            {"id": metric.pk, "agent_id": self.agent.agent_id, "value": 1},
            format="json",
        )
        self.assertEqual(r.status_code, 400)
        self.assertFalse(CheckResult.objects.filter(assigned_check=metric).exists())

    def post(self, check, status, more_info):
        return self.client.patch(
            "/api/v3/checkrunner/",
            {
                "id": check.pk,
                "agent_id": self.agent.agent_id,
                "status": status,
                "more_info": more_info,
            },
            format="json",
        )

    def test_agent_results_raise_and_resolve(self):
        for check in (
            self.make(
                check_type=CheckType.SYSTEMD,
                svc_name="nginx.service",
                fails_b4_alert=2,
                alert_severity=AlertSeverity.ERROR,
            ),
            self.make(
                check_type=CheckType.CONTAINER, container="web", fails_b4_alert=2
            ),
        ):
            r = self.post(check, "failing", "failed/failed, restarts 3")
            self.assertEqual(r.status_code, 200)
            result = CheckResult.objects.get(assigned_check=check)
            self.assertEqual(
                (result.status, result.fail_count, result.more_info),
                (CheckStatus.FAILING, 1, "failed/failed, restarts 3"),
            )
            self.assertFalse(check.alert.exists())

            self.post(check, "failing", "failed/failed, restarts 4")
            alert = check.alert.get(resolved=False)
            self.assertEqual(alert.severity, check.alert_severity)
            body = result.__class__.objects.get(pk=result.pk)._failure_body("S", True)
            self.assertEqual(body, "S - failed/failed, restarts 4")

            self.post(check, "passing", "active/running, restarts 0")
            result.refresh_from_db()
            self.assertEqual(
                (result.status, result.fail_count), (CheckStatus.PASSING, 0)
            )
            self.assertFalse(check.alert.filter(resolved=False).exists())
