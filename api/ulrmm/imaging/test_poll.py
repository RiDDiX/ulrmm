# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import base64
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import AsyncMock, patch
from urllib.parse import urlsplit

from django.test import override_settings
from model_bakery import baker
from rest_framework.test import APIClient

from deploy import envelope, signing
from deploy.models import AgentIdentity
from logs.models import AuditLog
from ulrmm.test import ULRMMTestCase

from alerts.models import Alert

from . import resolver
from .models import (
    BackupPolicy,
    BackupRun,
    DeviceBackupState,
    Image,
    Profile,
    Transfer,
)
from .native import CONFIG_HEADER, LEGACY_HOOKS, NO_IDENTITY, NOT_ASKED
from .service import backup_rows, queue_capture

GRANT_KEYS = {"url", "token", "claim", "expires_at", "network_mode", "image_id"}


class PollBase(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.authenticate()
        self.agent = baker.make(
            "agents.Agent",
            agent_id="poll-agent",
            plat="windows",
            goarch="amd64",
            time_zone="UTC",
        )
        self.authenticate_agent(self.agent)
        self.worker = self.client
        self.client = APIClient()
        self.client.force_authenticate(self.john)
        root = Path(self.enterContext(TemporaryDirectory()))
        self.enterContext(
            override_settings(
                ULRMM_IMAGING_ROOT=str(root),
                ULRMM_IMAGING_PUBLIC_ORIGIN="https://api.example.com",
                ULRMM_IMAGING_RESERVE_BYTES=0,
                ALLOWED_HOSTS=["api.example.com", "testserver"],
            )
        )
        self.uri = f"/imaging/agents/{self.agent.agent_id}/"
        self.url = f"/api/v3/{self.agent.agent_id}/imaging/"
        self.cap = dict(
            method="windows-wbadmin-tar-v1",
            ready=True,
            scope="Critical volumes",
            recovery="WinRE",
            reason="Ready",
            encryption="unencrypted source",
            source_id="gpt-test",
            device_uuid="90cb53c8-01ea-444d-b1f1-23abcd127ace",
            boot_mode="uefi",
            size=512 * 1024**2,
            sector_size=512,
        )
        self.assertEqual(self.poll().status_code, 204)

    def identity(self, state="active"):
        from deploy.tests.test_envelope import FakeAgent

        keys = {c["kid"]: base64.b64decode(c["ed"]) for c in signing.command_claim()}
        FakeAgent(self.agent.agent_id, keys).identity(self.agent)
        AgentIdentity.objects.filter(agent=self.agent).update(state=state)
        envelope.forget(self.agent)

    def poll(self, protocol=None, seal=False, **extra):
        body = {"capability": self.cap, **extra}
        if protocol:
            body.setdefault("protocol", protocol)
            body.setdefault("capabilities", [self.cap])
            version = self.state().config_version
            body.setdefault(
                "config",
                {
                    "version": version,
                    "hash": "",
                    "status": "none",
                    "errors": [],
                    "checks_version": version,
                },
            )
        headers = {"HTTP_X_ULRMM_SEAL": "1"} if seal else {}
        return self.worker.post(self.url, body, format="json", secure=True, **headers)

    def state(self):
        return DeviceBackupState.objects.get(agent=self.agent)

    def queue(self):
        r = self.client.post(self.uri + "capture/", {}, format="json")
        self.assertEqual(r.status_code, 202, r.data)
        return Image.objects.get(pk=r.data["id"])

    def schedule_point(self):
        profile, _ = backup_rows(self.agent)
        Profile.objects.filter(pk=profile.pk).update(
            overrides={"schedule": {"kind": "daily", "time": "03:00"}}
        )
        resolver.resolve_device(self.agent, cause="device")
        return queue_capture(
            Profile.objects.get(pk=profile.pk), "imaging scheduler", trigger="schedule"
        )


class TestPoll(PollBase):
    def test_legacy_poll_unchanged_shape(self):
        self.queue()
        r = self.poll()
        self.assertEqual(r.status_code, 200)
        self.assertEqual(set(r.data), GRANT_KEYS)
        self.assertEqual(self.state().protocol, 0)
        run = BackupRun.objects.get()
        self.assertEqual(
            (run.status, run.step, run.agent_protocol), ("running", "snapshot", 0)
        )
        self.assertEqual(Transfer.objects.get().run, run)

    def test_protocol2_claim_sealed(self):
        self.identity()
        image = self.queue()
        with patch(
            "imaging.native.envelope.seal_response", wraps=envelope.seal_response
        ) as seal:
            r = self.poll(protocol=2, seal=True)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r["X-ULRMM-Sealed"], "1")
        self.assertEqual(r[CONFIG_HEADER], str(self.state().config_version))
        data = seal.call_args.args[2]
        run = BackupRun.objects.get()
        self.assertTrue(GRANT_KEYS < set(data))
        self.assertEqual(data["run"], str(run.id))
        self.assertEqual(data["trigger"], "manual")
        self.assertIsNone(data["stop_at"])
        self.assertEqual(data["run_config"]["pause_max_minutes"], 30)
        self.assertEqual(data["hooks"], [])
        self.assertEqual(data["config_version"], self.state().config_version)
        grant = Transfer.objects.get(image=image)
        self.assertEqual((grant.authority, grant.run), ("user", run))
        self.assertEqual(grant.config_version, self.state().config_version)

    def test_unsealed_request_gets_no_claim_and_check_reason(self):
        self.identity()
        image = self.queue()
        r = self.poll(protocol=2)
        self.assertEqual(r.status_code, 204)
        image.refresh_from_db()
        self.assertEqual(image.reason, NOT_ASKED)
        self.assertFalse(Transfer.objects.exists())
        run = BackupRun.objects.get()
        self.assertEqual((run.status, run.deferred_reason), ("deferred", "sealing"))
        checks = {c["id"]: c for c in self.client.get(self.uri).data["checks"]}
        self.assertEqual(checks["agent.sealing"]["state"], "missing")
        self.assertEqual(checks["agent.sealing"]["detail"], NOT_ASKED)

    def test_inactive_identity_gets_no_claim(self):
        self.identity(state="quarantined")
        image = self.queue()
        r = self.poll(protocol=2, seal=True)
        self.assertEqual(r.status_code, 204)
        self.assertFalse(r.has_header("X-ULRMM-Sealed"))
        image.refresh_from_db()
        self.assertEqual(image.reason, NO_IDENTITY)
        self.assertFalse(Transfer.objects.exists())

    def test_legacy_with_hooks_gets_no_claim(self):
        script = baker.make(
            "scripts.Script", name="Dump", shell="powershell", script_body="x"
        )
        profile, _ = backup_rows(self.agent)
        hooks = [
            {
                "script_id": script.pk,
                "phase": "pre-backup",
                "args": [],
                "env_vars": [],
                "timeout": 60,
                "on_fail": "abort",
            }
        ]
        Profile.objects.filter(pk=profile.pk).update(overrides={"hooks": hooks})
        resolver.resolve_device(self.agent, cause="device")
        image = self.queue()
        self.assertEqual(self.poll().status_code, 204)
        image.refresh_from_db()
        self.assertEqual(image.reason, LEGACY_HOOKS)
        self.assertEqual(BackupRun.objects.get().deferred_reason, "legacy")
        checks = {c["id"]: c for c in self.client.get(self.uri).data["checks"]}
        self.assertEqual(checks["agent.config"]["state"], "missing")

    def test_policy_authority_without_operator(self):
        self.policy_claim()

    def policy_claim(self):
        image = self.schedule_point()
        self.assertIsNone(image.operator)
        self.assertEqual(image.trigger, "schedule")
        r = self.poll()
        self.assertEqual(r.status_code, 200, r.data)
        grant = Transfer.objects.get(image=image)
        self.assertEqual(
            (grant.user, grant.authority, grant.policy), (None, "policy", None)
        )
        self.assertTrue(
            AuditLog.objects.filter(
                message__contains="(authority the device schedule, run"
            ).exists()
        )
        return r

    def transfer(self, r, op="begin/"):
        client = APIClient(HTTP_AUTHORIZATION="Bearer " + r.data["token"])
        return client.post(
            urlsplit(r.data["url"]).path + op,
            {},
            format="json",
            secure=True,
            HTTP_HOST="api.example.com",
        )

    def test_policy_authority_recheck_on_transfer(self):
        r = self.policy_claim()
        Profile.objects.filter(agent=self.agent).update(overrides={})
        resolver.resolve_device(self.agent, cause="device")
        self.assertEqual(self.transfer(r).status_code, 403)

    def test_version_pinned_not_compared(self):
        r = self.policy_claim()
        pinned = Transfer.objects.get().config_version
        Profile.objects.filter(agent=self.agent).update(
            overrides={"schedule": {"kind": "daily", "time": "03:00"}, "smart": "off"}
        )
        _, state = resolver.resolve_device(self.agent, cause="device")
        self.assertGreater(state.config_version, pinned)
        self.assertEqual(self.transfer(r).status_code, 204)

    def test_fix_audit_once(self):
        check = {
            "id": "win.vss_service",
            "state": "fixed",
            "blocking": True,
            "detail": "",
            "fix": "Set VSS to manual.",
            "fix_argv": [
                "C:\\Windows\\System32\\sc.exe",
                "config",
                "VSS",
                "start=",
                "demand",
            ],
            "fixed_at": 1764000000000,
            "observed_at": 1764000000000,
        }
        for _ in range(2):
            self.assertEqual(self.poll(protocol=2, checks=[check]).status_code, 204)
        audits = AuditLog.objects.filter(
            message="Backup readiness fix win.vss_service applied: "
            "C:\\Windows\\System32\\sc.exe config VSS start= demand."
        )
        self.assertEqual(audits.count(), 1)

    def test_agent_check_with_blank_fields_accepted(self):
        check = {
            "id": "method.windows-wbadmin-tar-v1",
            "state": "ok",
            "blocking": True,
            "detail": "",
            "fix": "",
            "fix_argv": [],
            "fixed_at": None,
            "observed_at": 1764000000000,
        }
        r = self.poll(protocol=2, checks=[check], checks_at=1764000000000)
        self.assertEqual(r.status_code, 204, getattr(r, "data", None))
        self.assertEqual(self.state().checks, [check])

    def test_failure_report_with_protocol2_keys(self):
        image = self.queue()
        grant = self.poll()
        self.assertEqual(grant.status_code, 200)
        r = self.poll(
            protocol=2,
            config={"version": 0, "hash": "", "status": "none", "errors": []},
            checks=[],
            conditions={"on_ac": None, "up_since": 1764000000000, "events": []},
            image_id=str(image.id),
            failure="capture",
            claim=grant.data["claim"],
        )
        self.assertEqual(r.status_code, 204)
        image.refresh_from_db()
        self.assertIn("Native capture failed preflight", image.reason)
        self.assertEqual(BackupRun.objects.get().status, "interrupted")

    def test_capability_list_must_name_method(self):
        other = {**self.cap, "method": "macos-timemachine-disk-v1"}
        r = self.worker.post(
            self.url,
            {"capability": self.cap, "protocol": 2, "capabilities": [other]},
            format="json",
            secure=True,
        )
        self.assertEqual(r.status_code, 400)
        self.assertIn("The capability list must name the reported method.", str(r.data))

    def test_check_on_legacy_agent_409(self):
        url = self.uri + "check/"
        with patch("agents.models.Agent.nats_cmd", new_callable=AsyncMock) as nats:
            r = self.client.post(url, {}, format="json")
            self.assertEqual(r.status_code, 409)
            self.assertEqual(
                r.data["detail"],
                "Update the agent to run readiness checks from the dashboard.",
            )
            nats.assert_not_called()
            self.poll(protocol=2)
            r = self.client.post(url, {}, format="json")
        self.assertEqual((r.status_code, r.data), (202, {}))
        nats.assert_awaited_once_with({"func": "imagingcheck"}, wait=False)
        self.assertTrue(
            AuditLog.objects.filter(
                message="Backup readiness check requested."
            ).exists()
        )


def agent_check(state="ok", **kw):
    return {
        "id": "method.windows-wbadmin-tar-v1",
        "state": state,
        "blocking": True,
        "detail": "",
        "fix": "",
        "fix_argv": [],
        "fixed_at": None,
        "observed_at": 1764000000000,
        **kw,
    }


class TestPollReview(PollBase):
    def transfer(self, grant, op="begin/"):
        client = APIClient(HTTP_AUTHORIZATION="Bearer " + grant.data["token"])
        return client.post(
            urlsplit(grant.data["url"]).path + op,
            {},
            format="json",
            secure=True,
            HTTP_HOST="api.example.com",
        )

    def test_policy_grant_recheck_needs_no_full_scan(self):
        policy = BackupPolicy.objects.create(
            name="Site",
            scope="site",
            site=self.agent.site,
            config={"schedule": {"kind": "daily", "time": "03:00"}},
        )
        profile, _ = resolver.resolve_device(self.agent, cause="policy")
        image = queue_capture(profile, "imaging scheduler", trigger="schedule")
        grant = self.poll()
        self.assertEqual(grant.status_code, 200, grant.data)
        self.assertEqual(Transfer.objects.get(image=image).policy, policy)
        with patch("imaging.resolver.reach", side_effect=AssertionError("full scan")):
            self.assertEqual(self.transfer(grant).status_code, 204)

    def test_check_ids_unique_and_times_bounded(self):
        r = self.poll(protocol=2, checks=[agent_check(), agent_check()])
        self.assertEqual(r.status_code, 400)
        self.assertIn("Check ids must be unique.", str(r.data))
        r = self.poll(protocol=2, checks=[agent_check()], checks_at=10**16)
        self.assertEqual(r.status_code, 400)
        r = self.poll(protocol=2, conditions={"up_since": 10**16})
        self.assertEqual(r.status_code, 400)

    def test_fix_audit_only_for_a_newer_past_time(self):
        from django.utils import timezone

        future = int(timezone.now().timestamp() * 1000) + 10**9
        for fixed_at in (1764000000000, future, 1763000000000):
            check = agent_check("fixed", id="win.vss_service", fixed_at=fixed_at)
            self.assertEqual(self.poll(protocol=2, checks=[check]).status_code, 204)
        audits = AuditLog.objects.filter(message__startswith="Backup readiness fix")
        self.assertEqual(audits.count(), 1)

    def test_flapping_readiness_reopens_one_alert(self):
        self.identity()
        bad = agent_check("missing", detail="Text the device chose.")
        for check in (agent_check(), bad, agent_check(), bad):
            self.assertEqual(
                self.poll(protocol=2, seal=True, checks=[check]).status_code, 204
            )
        alerts = Alert.objects.filter(agent=self.agent, alert_type="backup")
        self.assertEqual(alerts.count(), 1)
        alert = alerts.get()
        self.assertEqual(
            (alert.message, alert.resolved), ("Backups are no longer ready.", False)
        )

    def test_protocol2_gate_is_the_stored_entry(self):
        self.identity()
        image = self.queue()
        gate = {**self.cap, "ready": False, "reason": "Volume busy."}
        r = self.poll(protocol=2, seal=True, capabilities=[gate])
        self.assertEqual(r.status_code, 204)
        image.refresh_from_db()
        self.assertEqual(image.reason, "Volume busy.")
        self.assertFalse(Transfer.objects.exists())
        r = self.poll(protocol=2, capabilities=[self.cap, self.cap])
        self.assertEqual(r.status_code, 400)
        self.assertIn("Report each method once.", str(r.data))

    def test_checks_of_an_older_document_count_for_nothing(self):
        self.identity()
        self.poll(protocol=2, seal=True, checks=[agent_check()])
        self.assertTrue(self.state().ready)
        image = self.queue()
        version = self.state().config_version
        self.assertEqual(version, 1)
        bad = agent_check("missing", detail="Not yet.")
        stale = {
            "version": 1,
            "hash": "",
            "status": "none",
            "errors": [],
            "checks_version": 0,
        }
        r = self.poll(protocol=2, seal=True, checks=[bad], config=stale)
        self.assertEqual((r.status_code, r[CONFIG_HEADER]), (204, "1"))
        state = self.state()
        self.assertTrue(state.ready)
        self.assertEqual(state.checks, [agent_check()])
        self.assertFalse(Alert.objects.exists())
        self.assertFalse(Transfer.objects.exists())
        r = self.poll(protocol=2, seal=True, checks=[bad])
        self.assertEqual(r.status_code, 204)
        self.assertFalse(self.state().ready)
        self.assertTrue(Alert.objects.filter(resolved=False).exists())
        r = self.poll(protocol=2, seal=True, checks=[agent_check()])
        self.assertEqual(r.status_code, 200)
        self.assertTrue(Transfer.objects.filter(image=image).exists())
        self.assertFalse(Alert.objects.filter(resolved=False).exists())

    def test_complete_agent_body(self):
        state = self.state()
        body = {
            "protocol": 2,
            "capability": self.cap,
            "capabilities": [self.cap],
            "config": {
                "version": state.config_version,
                "hash": state.config_hash,
                "status": "applied",
                "errors": [],
                "checks_version": state.config_version,
            },
            "checks": [agent_check()],
            "checks_at": 1764000000000,
            "conditions": {"on_ac": None, "up_since": 1764000000000, "events": []},
            "deferred": "",
        }
        r = self.worker.post(self.url, body, format="json", secure=True)
        self.assertEqual(r.status_code, 204, getattr(r, "data", None))
        self.assertEqual(r[CONFIG_HEADER], str(state.config_version))
        state = self.state()
        self.assertEqual((state.ack_status, state.checks), ("applied", [agent_check()]))


class TestPollLab(PollBase):
    def test_catch_up_delay_wakes_the_agent_once(self):
        from datetime import timedelta

        from django.utils import timezone

        from ulrmm.test import LOCMEM_CACHE

        # the test default cache keeps nothing, so a real one counts the wakes
        self.enterContext(override_settings(CACHES=LOCMEM_CACHE))

        from .service import backup_rows, queue_capture

        profile, _ = backup_rows(self.agent)
        Profile.objects.filter(pk=profile.pk).update(
            overrides={"schedule": {"kind": "daily", "time": "03:00"}}
        )
        resolver.resolve_device(self.agent, cause="device")
        image = queue_capture(
            Profile.objects.get(pk=profile.pk), "imaging scheduler", trigger="schedule"
        )
        Image.objects.filter(pk=image.pk).update(
            created_at=timezone.now() - timedelta(hours=1)
        )
        DeviceBackupState.objects.filter(agent=self.agent).update(
            last_poll_at=timezone.now() - timedelta(minutes=20)
        )
        with (
            patch("imaging.tasks.wake_imaging_agent.apply_async") as wake,
            self.captureOnCommitCallbacks(execute=True),
        ):
            self.assertEqual(self.poll().status_code, 204)
            self.assertEqual(self.poll().status_code, 204)
        wake.assert_called_once()
        up = self.state().conditions["up_since"]
        start = wake.call_args.kwargs["eta"]
        self.assertEqual(int(start.timestamp() * 1000), up + 10 * 60 * 1000)

    def test_sealing_error_ack_with_empty_hash(self):
        state = self.state()
        body = {
            "protocol": 2,
            "capability": self.cap,
            "capabilities": [self.cap],
            "config": {
                "version": state.config_version,
                "hash": "",
                "status": "error",
                "errors": [
                    {"field": "sealing", "message": "The enrolment key does not match."}
                ],
                "checks_version": state.config_version,
            },
            "checks": [agent_check()],
            "checks_at": 1764000000000,
            "conditions": {"on_ac": None, "up_since": 1764000000000, "events": []},
            "deferred": "",
        }
        r = self.worker.post(self.url, body, format="json", secure=True)
        self.assertEqual(r.status_code, 204, getattr(r, "data", None))
        state = self.state()
        self.assertEqual((state.ack_status, state.acked_hash), ("error", ""))
        self.assertIn("config_error", state.alerts)
        alert = Alert.objects.get(pk=state.alerts["config_error"])
        sync = self.client.get(self.uri).data["sync"]
        self.assertEqual(sync["state"], "error")
        self.assertEqual(sync["errors"][0]["field"], "sealing")
        body["config"] = {
            **body["config"],
            "hash": state.config_hash,
            "status": "applied",
            "errors": [],
        }
        self.assertEqual(
            self.worker.post(self.url, body, format="json", secure=True).status_code,
            204,
        )
        self.assertNotIn("config_error", self.state().alerts)
        alert.refresh_from_db()
        self.assertTrue(alert.resolved)


class TestSealingRefusal(PollBase):
    def ack(self, status, field="sealing", checks_version=None, digest=""):
        state = self.state()
        errors = (
            [{"field": field, "message": "The enrolment key does not match."}]
            if status == "error"
            else []
        )
        body = {
            "protocol": 2,
            "capability": self.cap,
            "capabilities": [self.cap],
            "config": {
                "version": state.config_version,
                "hash": digest,
                "status": status,
                "errors": errors,
                "checks_version": (
                    state.config_version if checks_version is None else checks_version
                ),
            },
            "checks": [agent_check()],
            "checks_at": 1764000000000,
            "conditions": {"on_ac": None, "up_since": 1764000000000, "events": []},
            "deferred": "",
        }
        headers = {"HTTP_X_ULRMM_SEAL": "1"}
        return self.worker.post(self.url, body, format="json", secure=True, **headers)

    def test_sealing_refusal_makes_the_device_not_ready(self):
        self.identity()
        self.assertEqual(self.ack("none").status_code, 204)
        self.assertTrue(self.state().ready)
        image = self.queue()
        # the agent cannot open the sealed document, so its checks are older
        self.assertEqual(self.ack("error", checks_version=0).status_code, 204)
        state = self.state()
        message = "The enrolment key does not match."
        self.assertEqual((state.ready, state.not_ready_reason), (False, message))
        self.assertIn("readiness_lost", state.alerts)
        data = self.client.get(self.uri).data
        checks = {c["id"]: c for c in data["checks"]}
        self.assertEqual(
            (checks["agent.sealing"]["state"], checks["agent.sealing"]["detail"]),
            ("missing", message),
        )
        self.assertEqual((data["ready"], data["not_ready_reason"]), (False, message))
        self.assertEqual(self.ack("error").status_code, 204)
        image.refresh_from_db()
        self.assertEqual(image.status, "waiting")
        self.assertEqual(
            BackupRun.objects.get(image=image).deferred_reason, "not_ready"
        )
        self.assertFalse(Transfer.objects.exists())
        r = self.ack("applied", digest=self.state().config_hash)
        self.assertEqual(r.status_code, 200)
        state = self.state()
        self.assertTrue(state.ready)
        self.assertNotIn("readiness_lost", state.alerts)

    def test_other_refused_field_leaves_sealing_alone(self):
        self.identity()
        self.assertEqual(self.ack("error", field="network_mode").status_code, 204)
        checks = {c["id"]: c for c in self.client.get(self.uri).data["checks"]}
        self.assertEqual(checks["agent.sealing"]["state"], "ok")
        self.assertTrue(self.state().ready)


class TestSealingRefusalPoint(TestSealingRefusal):
    def test_stale_refusal_tells_the_waiting_point(self):
        self.identity()
        self.assertEqual(self.ack("none").status_code, 204)
        image = self.queue()
        before = Image.objects.get(pk=image.pk).reason
        # a stale poll without a refusal leaves the point alone
        self.assertEqual(self.ack("none", checks_version=0).status_code, 204)
        self.assertEqual(Image.objects.get(pk=image.pk).reason, before)
        self.assertFalse(BackupRun.objects.exists())
        self.assertEqual(self.ack("error", checks_version=0).status_code, 204)
        image.refresh_from_db()
        self.assertEqual(
            (image.status, image.reason),
            ("waiting", "The enrolment key does not match."),
        )
        self.assertEqual(BackupRun.objects.get().deferred_reason, "not_ready")
        r = self.ack("applied", digest=self.state().config_hash)
        self.assertEqual(r.status_code, 200)
        self.assertTrue(Transfer.objects.filter(image=image).exists())
