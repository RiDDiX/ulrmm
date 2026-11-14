# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import datetime as dt
import hashlib
import hmac
import json
from unittest.mock import MagicMock, patch

import requests
from django.utils import timezone as djangotime
from model_bakery import baker

from alerts.models import Alert
from logs.models import AuditLog, DebugLog
from remote.utils import decrypt_secret, encrypt_secret
from ulrmm.constants import AlertSeverity
from ulrmm.test import ULRMMTestCase

from . import dispatch as d
from . import senders
from .models import HKDF_INFO, Channel, Notification, Route, State

DELAY = "notify.tasks.send_notifications_task.delay"
REQUEST = "notify.senders.requests.request"
INTERNAL = "notify.senders._is_internal_url"
TG_TOKEN = "123456:ABCDEFGHIJKLMNOPQRSTUVWXYZ_abc"


def ok(status=200, text=""):
    r = MagicMock(status_code=status, text=text, history=[])
    return r


def channel(kind="ntfy", secret="", **kwargs):
    config = {
        "ntfy": {"topic": "rmm"},
        "matrix": {"homeserver": "https://matrix.example.org", "room_id": "!a:x.org"},
        "telegram": {"chat_id": "-100123"},
        "webhook": {"url": "https://hooks.example.org/in"},
        "slack": {},
        "teams": {},
        "email": {"recipients": ["ops@example.org"]},
    }[kind]
    return baker.make(
        "notify.Channel",
        name=kind,
        kind=kind,
        config=kwargs.pop("config", config),
        secret=encrypt_secret(secret, HKDF_INFO) if secret else "",
        **kwargs,
    )


def route(channels, **kwargs):
    r = baker.make("notify.Route", name="r", **kwargs)
    r.channels.set(channels)
    return r


def event(**kwargs):
    return {
        "source": "check",
        "severity": "error",
        "title": "disk full",
        "body": "C: 99%",
        **kwargs,
    }


class TestDispatch(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.agent = baker.make_recipe("agents.agent")

    @patch(DELAY)
    def test_no_routes_or_channels_is_fine(self, delay):
        self.assertEqual(d.dispatch(event()), 0)
        route([])
        self.assertEqual(d.dispatch(event(agent=self.agent)), 0)
        delay.assert_not_called()
        self.assertFalse(Notification.objects.exists())

    def test_never_raises(self):
        with patch("notify.dispatch._dispatch", side_effect=RuntimeError("boom")):
            self.assertEqual(d.dispatch(event()), 0)
        self.assertTrue(DebugLog.objects.filter(message__contains="boom").exists())

    @patch(DELAY)
    def test_route_matching(self, delay):
        a, b, off = channel(), channel("slack", "https://hooks.slack.com/x"), channel()
        off.enabled = False
        off.save()
        quiet = channel(min_severity=AlertSeverity.ERROR)
        route([a, b, off], sources=["check"], severities=["error", "warning"])
        route([a, quiet], sources=["netmon"])

        with self.captureOnCommitCallbacks(execute=True):
            self.assertEqual(d.dispatch(event()), 2)
        rows = Notification.objects.order_by("pk")
        self.assertEqual({r.channel_id for r in rows}, {a.pk, b.pk})
        self.assertEqual(rows[0].state, State.QUEUED)
        delay.assert_called_once_with([r.pk for r in rows])

        # info is below the error channel, netmon matches the second route only
        self.assertEqual(d.dispatch(event(source="netmon", severity="info")), 1)
        self.assertEqual(d.dispatch(event(source="vuln")), 0)
        self.assertEqual(d.dispatch(event(severity="info")), 0)

    @patch(DELAY)
    def test_dedupe_key(self, delay):
        route([channel()])
        self.assertEqual(d.dispatch(event(dedupe_key="k1")), 1)
        self.assertEqual(d.dispatch(event(dedupe_key="k1")), 0)
        self.assertEqual(d.dispatch(event(dedupe_key="k2")), 1)

        # 24 hours by default, 0 = for good
        Notification.objects.update(created=djangotime.now() - dt.timedelta(days=2))
        self.assertEqual(d.dispatch(event(dedupe_key="k1")), 1)
        self.assertEqual(d.dispatch(event(dedupe_key="k2", dedupe_hours=0)), 0)

    @patch(DELAY)
    def test_dedupe_check_holds_a_lock(self, delay):
        from django.db import connection
        from django.test.utils import CaptureQueriesContext

        route([channel()])
        with CaptureQueriesContext(
            connection
        ) as queries, self.captureOnCommitCallbacks(execute=True):
            self.assertEqual(d.dispatch(event(dedupe_key="k1")), 1)
        sql = [q["sql"] for q in queries.captured_queries]
        lock = next(i for i, q in enumerate(sql) if "pg_advisory_xact_lock" in q)
        insert = next(i for i, q in enumerate(sql) if q.startswith("INSERT"))
        self.assertLess(lock, insert)
        delay.assert_called_once()

    @patch(DELAY)
    def test_maintenance_mutes_unless_the_route_says_otherwise(self, delay):
        muted = route([channel()])
        loud = route([channel("slack", "https://hooks.slack.com/x")])
        loud.mute_in_maintenance = False
        loud.save()

        self.assertEqual(d.dispatch(event(agent=self.agent)), 2)
        self.agent.maintenance_mode = True
        self.agent.save()
        self.assertEqual(d.dispatch(event(agent=self.agent)), 1)
        self.assertEqual(Notification.objects.last().route, loud)

        # an open maintenance window counts too
        self.agent.maintenance_mode = False
        self.agent.save()
        baker.make(
            "patches.ScheduleRun",
            agent=self.agent,
            state="installing",
            schedule__kind="maintenance",
        )
        self.assertEqual(d.dispatch(event(agent=self.agent)), 1)
        self.assertNotEqual(Notification.objects.last().route, muted)


class TestAlertHooks(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.agent = baker.make_recipe(
            "agents.overdue_agent", overdue_dashboard_alert=True
        )
        self.channel = channel()
        route([self.channel], sources=["agent"])

    @patch(DELAY)
    def test_failure_and_resolve_notify_once(self, delay):
        Alert.handle_alert_failure(self.agent)
        Alert.handle_alert_failure(self.agent)
        row = Notification.objects.get()
        alert = Alert.objects.get(agent=self.agent)
        self.assertEqual(row.alert, alert)
        self.assertEqual(row.source, "agent")
        self.assertEqual(row.severity, AlertSeverity.ERROR)
        self.assertTrue(row.title.startswith(f"{self.agent.hostname} in "))

        Alert.handle_alert_resolve(self.agent)
        resolved = Notification.objects.order_by("pk").last()
        self.assertTrue(resolved.title.startswith("Resolved: "))
        self.assertEqual(Notification.objects.count(), 2)

    @patch(DELAY)
    def test_no_resolve_message_without_a_failure_message(self, delay):
        Route.objects.all().delete()
        Alert.handle_alert_failure(self.agent)
        route([self.channel], sources=["agent"])
        Alert.handle_alert_resolve(self.agent)
        self.assertFalse(Notification.objects.exists())

    @patch(DELAY)
    def test_tamper_alerts_keep_their_source(self, delay):
        tamper_route = route([self.channel], sources=["tamper"])
        alert = baker.make(
            "alerts.Alert",
            agent=self.agent,
            alert_type="agent",
            severity=AlertSeverity.WARNING,
            message="agent stopped",
        )
        self.assertEqual(d.notify_alert(alert), 1)
        alert.resolve()
        self.assertEqual(d.notify_alert(alert, resolved=True), 1)
        self.assertEqual(
            {(n.source, n.route_id) for n in Notification.objects.all()},
            {("tamper", tamper_route.pk)},
        )


class TestSenders(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.n = {
            "source": "check",
            "severity": "warning",
            "title": "disk",
            "body": "C: 91%",
            "alert": 7,
            "agent_id": "abc",
            "escalation_level": 0,
        }

    def send(self, ch):
        with patch(INTERNAL, return_value=False), patch(
            REQUEST, return_value=ok()
        ) as req:
            d.send(ch, self.n)
        return req

    def test_matrix(self):
        req = self.send(channel("matrix", "syt_token_123"))
        method, url = req.call_args.args
        self.assertEqual(method, "PUT")
        self.assertTrue(
            url.startswith(
                "https://matrix.example.org/_matrix/client/v3/rooms/%21a%3Ax.org"
                "/send/m.room.message/"
            )
        )
        kw = req.call_args.kwargs
        self.assertEqual(kw["headers"]["Authorization"], "Bearer syt_token_123")
        self.assertEqual(
            kw["json"], {"msgtype": "m.text", "body": "[warning] disk\nC: 91%"}
        )
        self.assertEqual(kw["timeout"], senders.TIMEOUT)
        self.assertFalse(kw["allow_redirects"])

    def test_telegram_plain_text(self):
        req = self.send(channel("telegram", TG_TOKEN))
        self.assertEqual(
            req.call_args.args[1], f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage"
        )
        body = req.call_args.kwargs["json"]
        self.assertEqual(body["chat_id"], "-100123")
        self.assertNotIn("parse_mode", body)

    def test_ntfy_headers(self):
        self.n["title"] = "Störung"
        req = self.send(channel("ntfy", "tk_abc"))
        self.assertEqual(req.call_args.args[1], "https://ntfy.sh/rmm")
        h = req.call_args.kwargs["headers"]
        self.assertEqual(h["Priority"], "4")
        self.assertEqual(h["Tags"], "warning,check")
        self.assertEqual(h["Authorization"], "Bearer tk_abc")
        self.assertTrue(h["Title"].startswith("=?utf-8?"))
        self.assertEqual(req.call_args.kwargs["data"], b"C: 91%")

    def test_slack_and_teams_post_to_the_secret_url(self):
        req = self.send(channel("slack", "https://hooks.example.com/abc"))
        self.assertEqual(req.call_args.args, ("POST", "https://hooks.example.com/abc"))
        self.assertEqual(
            req.call_args.kwargs["json"], {"text": "[warning] disk\nC: 91%"}
        )

        req = self.send(channel("teams", "https://x.webhook.office.com/abc"))
        self.assertEqual(req.call_args.args[1], "https://x.webhook.office.com/abc")
        card = req.call_args.kwargs["json"]["attachments"][0]["content"]
        self.assertEqual(card["body"][0]["text"], "[warning] disk\nC: 91%")

    def test_webhook_signature(self):
        req = self.send(channel("webhook", "signing-key-1"))
        body = req.call_args.kwargs["data"]
        expected = hmac.new(b"signing-key-1", body, hashlib.sha256).hexdigest()
        self.assertEqual(
            req.call_args.kwargs["headers"]["X-Signature"], f"sha256={expected}"
        )
        sent = json.loads(body)
        self.assertEqual(sent["alert_id"], 7)
        self.assertEqual(sent["agent_id"], "abc")

        # no secret, no signature
        req = self.send(channel("webhook"))
        self.assertNotIn("X-Signature", req.call_args.kwargs["headers"])

    @patch("core.models.smtplib.SMTP")
    def test_email(self, smtp):
        core = self.coresettings
        core.smtp_from_email = "rmm@example.org"
        core.smtp_host = "mail.example.org"
        core.smtp_port = 25
        core.smtp_requires_auth = False
        core.save()
        d.send(channel("email"), self.n)
        msg = smtp.return_value.send_message.call_args.args[0]
        self.assertEqual(msg["To"], "ops@example.org")
        self.assertEqual(msg["Subject"], "disk")

        smtp.side_effect = OSError("refused")
        with self.assertRaises(senders.SendError):
            d.send(channel("email"), self.n)

    def test_errors_never_carry_the_token(self):
        ch = channel("telegram", TG_TOKEN)
        with patch(INTERNAL, return_value=False), patch(
            REQUEST,
            side_effect=requests.ConnectionError(
                f"https://api.telegram.org/bot{TG_TOKEN}"
            ),
        ):
            with self.assertRaises(senders.SendError) as e:
                d.send(ch, self.n)
        self.assertNotIn(TG_TOKEN, str(e.exception))

        with patch(INTERNAL, return_value=False), patch(
            REQUEST, return_value=ok(403, "forbidden")
        ):
            with self.assertRaisesMessage(senders.SendError, "HTTP 403 forbidden"):
                d.send(ch, self.n)

    def test_only_https_and_not_this_server(self):
        ch = channel("webhook", config={"url": "http://hooks.example.org/in"})
        with patch(REQUEST) as req:
            with self.assertRaisesMessage(senders.SendError, "https"):
                d.send(ch, self.n)
            ch.config = {"url": "https://127.0.0.1/in"}
            with self.assertRaisesMessage(senders.SendError, "this server"):
                d.send(ch, self.n)
        req.assert_not_called()


class TestDelivery(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.coresettings.default_time_zone = "UTC"
        self.coresettings.save()
        self.ch = channel()

    def row(self, **kwargs):
        kwargs.setdefault("title", "t")
        return baker.make(
            "notify.Notification",
            channel=self.ch,
            source="check",
            severity="error",
            **kwargs,
        )

    def test_sent_and_failed(self):
        row = self.row()
        with patch(INTERNAL, return_value=False), patch(REQUEST, return_value=ok()):
            d.deliver([row.pk])
        row.refresh_from_db()
        self.ch.refresh_from_db()
        self.assertEqual(row.state, State.SENT)
        self.assertIsNotNone(row.sent_at)
        self.assertIsNotNone(self.ch.last_sent)

        row = self.row()
        with patch(INTERNAL, return_value=False), patch(REQUEST, return_value=ok(500)):
            d.deliver([row.pk])
        row.refresh_from_db()
        self.ch.refresh_from_db()
        self.assertEqual(row.state, State.FAILED)
        self.assertEqual(row.error, "HTTP 500")
        self.assertEqual(self.ch.last_error, "HTTP 500")
        self.assertTrue(DebugLog.objects.filter(message__contains="HTTP 500").exists())

    def test_quiet_hours_hold_then_one_digest(self):
        now = djangotime.now()
        self.ch.quiet_start = (now - dt.timedelta(hours=1)).time()
        self.ch.quiet_end = (now + dt.timedelta(hours=1)).time()
        self.ch.save()
        rows = [self.row(title=f"t{i}") for i in range(3)]
        with patch(REQUEST) as req:
            d.deliver([r.pk for r in rows])
            d.flush_held(now)
        req.assert_not_called()
        self.assertEqual(Notification.objects.filter(state=State.HELD).count(), 3)

        with patch(INTERNAL, return_value=False), patch(
            REQUEST, return_value=ok()
        ) as req:
            d.flush_held(now + dt.timedelta(hours=2))
        req.assert_called_once()
        self.assertIn("[error] t2", req.call_args.kwargs["data"].decode())
        self.assertEqual(
            Notification.objects.filter(
                pk__in=[r.pk for r in rows], state=State.SENT
            ).count(),
            3,
        )
        self.assertFalse(Notification.objects.filter(state=State.HELD).exists())

    def test_quiet_hours_over_midnight(self):
        self.ch.quiet_start, self.ch.quiet_end = dt.time(22), dt.time(6)
        at = lambda h: dt.datetime(2026, 10, 9, h, tzinfo=dt.timezone.utc)  # noqa
        self.assertTrue(d.in_quiet_hours(self.ch, at(23)))
        self.assertTrue(d.in_quiet_hours(self.ch, at(5)))
        self.assertFalse(d.in_quiet_hours(self.ch, at(6)))
        self.assertFalse(d.in_quiet_hours(self.ch, at(12)))

    def test_rate_limit_one_summary(self):
        now = djangotime.now()
        Notification.objects.bulk_create(
            Notification(
                channel=self.ch,
                source="check",
                title="x",
                state=State.SENT,
                sent_at=now,
            )
            for _ in range(60)
        )
        first, second = self.row(), self.row()
        with patch(INTERNAL, return_value=False), patch(
            REQUEST, return_value=ok()
        ) as req:
            d.deliver([first.pk])
            d.deliver([second.pk])
        req.assert_called_once()
        self.assertIn(b"More than 60", req.call_args.kwargs["data"])
        for row in (first, second):
            row.refresh_from_db()
            self.assertEqual(row.state, State.DROPPED)

    def test_failing_channel_pauses_and_rows_wait(self):
        rows = [self.row(title=f"t{i}") for i in range(7)]
        recovery = self.row(dedupe_key="alert:1:resolved")
        with patch(INTERNAL, return_value=False), patch(
            REQUEST, side_effect=requests.ConnectionError("down")
        ) as req:
            d.deliver([r.pk for r in rows] + [recovery.pk])
        self.assertEqual(req.call_count, d.PAUSE_AFTER)
        rows[-1].refresh_from_db()
        self.assertEqual((rows[-1].state, rows[-1].error), (State.QUEUED, d.PAUSED))
        recovery.refresh_from_db()
        self.assertEqual((recovery.state, recovery.error), (State.QUEUED, d.PAUSED))

        # once the failures are older than the pause, the queued recovery goes out
        Notification.objects.exclude(pk=recovery.pk).update(
            created=djangotime.now() - dt.timedelta(minutes=6)
        )
        Notification.objects.filter(pk=recovery.pk).update(
            created=djangotime.now() - dt.timedelta(minutes=11)
        )
        with patch(DELAY) as delay:
            self.assertEqual(d.requeue_stale(djangotime.now()), 1)
        self.assertEqual(delay.call_args.args[0], [recovery.pk])
        with patch(INTERNAL, return_value=False), patch(REQUEST, return_value=ok()):
            d.deliver([recovery.pk])
        recovery.refresh_from_db()
        self.assertEqual((recovery.state, recovery.error), (State.SENT, ""))

    def test_recovery_passes_the_rate_limit(self):
        now = djangotime.now()
        Notification.objects.bulk_create(
            Notification(
                channel=self.ch,
                source="check",
                title="x",
                state=State.SENT,
                sent_at=now,
            )
            for _ in range(60)
        )
        plain, recovery = self.row(), self.row(dedupe_key="alert:7:resolved")
        with patch(INTERNAL, return_value=False), patch(REQUEST, return_value=ok()):
            d.deliver([plain.pk, recovery.pk])
        plain.refresh_from_db()
        recovery.refresh_from_db()
        self.assertEqual((plain.state, recovery.state), (State.DROPPED, State.SENT))

    def test_paused_row_is_retried(self):
        # failures within the pause, then a plain row that waits for it
        for _ in range(d.PAUSE_AFTER):
            self.row(state=State.FAILED, error="down")
        row = self.row()
        with patch(INTERNAL, return_value=False), patch(REQUEST) as req:
            d.deliver([row.pk])
        req.assert_not_called()
        row.refresh_from_db()
        self.assertEqual((row.state, row.error), (State.QUEUED, d.PAUSED))

        old = djangotime.now() - dt.timedelta(minutes=11)
        Notification.objects.update(created=old)
        with patch(DELAY) as delay:
            self.assertEqual(d.requeue_stale(djangotime.now()), 1)
        with patch(INTERNAL, return_value=False), patch(REQUEST, return_value=ok()):
            d.deliver(delay.call_args.args[0])
        row.refresh_from_db()
        self.assertEqual((row.state, row.error), (State.SENT, ""))

    def test_claimed_row_is_sent_once(self):
        first, second = self.row(), self.row()

        def other_task_takes_second(*args, **kwargs):
            Notification.objects.filter(pk=second.pk).update(state=State.SENDING)
            return ok()

        with patch(INTERNAL, return_value=False), patch(
            REQUEST, side_effect=other_task_takes_second
        ) as req:
            d.deliver([first.pk, second.pk])
        self.assertEqual(req.call_count, 1)
        second.refresh_from_db()
        self.assertEqual(second.state, State.SENDING)

        # a worker that died while sending: the row goes out again later
        Notification.objects.filter(pk=second.pk).update(
            created=djangotime.now() - dt.timedelta(minutes=11)
        )
        with patch(DELAY) as delay:
            self.assertEqual(d.requeue_stale(djangotime.now()), 1)
        self.assertEqual(delay.call_args.args[0], [second.pk])

    def test_fresh_queued_rows_are_not_requeued(self):
        self.row()
        with patch(DELAY) as delay:
            self.assertEqual(d.requeue_stale(djangotime.now()), 0)
        delay.assert_not_called()


class TestEscalation(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.agent = baker.make_recipe("agents.agent")
        self.first, self.boss = channel(), channel("slack", "https://hooks.x.org/a")
        self.route = route([self.first], escalate_after_minutes=15)
        self.route.escalate_to.set([self.boss])
        self.alert = baker.make(
            "alerts.Alert", agent=self.agent, severity="error", message="down"
        )
        row = baker.make(
            "notify.Notification",
            route=self.route,
            channel=self.first,
            alert=self.alert,
            source="agent",
            severity="error",
            title="down",
        )
        Notification.objects.filter(pk=row.pk).update(
            created=djangotime.now() - dt.timedelta(minutes=20)
        )

    @patch(DELAY)
    def test_once_per_route(self, delay):
        now = djangotime.now()
        d.escalate(now)
        row = Notification.objects.get(escalation_level=1)
        self.assertEqual(row.channel, self.boss)
        self.assertEqual(row.title, "Escalated: down")
        delay.assert_called_once_with([row.pk])

        d.escalate(now)
        self.assertEqual(Notification.objects.filter(escalation_level=1).count(), 1)

    @patch(DELAY)
    def test_not_before_time_nor_when_resolved(self, delay):
        d.escalate(djangotime.now() - dt.timedelta(minutes=10))
        self.alert.resolve()
        d.escalate(djangotime.now())
        self.assertFalse(Notification.objects.filter(escalation_level=1).exists())
        delay.assert_not_called()


class TestViews(ULRMMTestCase):
    def setUp(self):
        self.setup_coresettings()
        self.authenticate()

    def test_channel_secret_is_write_only(self):
        r = self.client.post(
            "/notify/channels/",
            {
                "name": "ops",
                "kind": "telegram",
                "config": {"chat_id": "-100123", "other": "dropped"},
                "secret": TG_TOKEN,
            },
            format="json",
        )
        self.assertEqual(r.status_code, 201, r.data)
        self.assertNotIn("secret", r.data)
        self.assertTrue(r.data["secret_set"])
        self.assertEqual(r.data["config"], {"chat_id": "-100123"})
        ch = Channel.objects.get()
        self.assertEqual(decrypt_secret(ch.secret, HKDF_INFO), TG_TOKEN)
        audit = json.dumps(
            AuditLog.objects.filter(object_type="channel").last().after_value
        )
        self.assertNotIn(TG_TOKEN, audit)
        self.assertIn("hmac:", audit)

        # blank keeps it, clear drops it, a telegram channel needs one
        r = self.client.patch(
            f"/notify/channels/{ch.pk}/", {"name": "ops2", "secret": ""}, format="json"
        )
        self.assertEqual(r.status_code, 200, r.data)
        ch.refresh_from_db()
        self.assertEqual(decrypt_secret(ch.secret, HKDF_INFO), TG_TOKEN)
        r = self.client.patch(
            f"/notify/channels/{ch.pk}/", {"secret_clear": True}, format="json"
        )
        self.assertEqual(r.status_code, 400)
        r = self.client.patch(
            f"/notify/channels/{ch.pk}/", {"kind": "slack"}, format="json"
        )
        self.assertEqual(r.status_code, 400)

        # the stored token never follows a new homeserver
        mx = channel("matrix", "tokentoken")
        url = f"/notify/channels/{mx.pk}/"
        cfg = {"homeserver": "https://evil.example", "room_id": "!a:x.org"}
        r = self.client.patch(url, {"config": cfg}, format="json")
        self.assertEqual(r.status_code, 400)
        self.assertIn("secret", r.data)
        r = self.client.patch(
            url, {"config": cfg, "secret": "newtoken1"}, format="json"
        )
        self.assertEqual(r.status_code, 200, r.data)
        r = self.client.patch(url, {"name": "mx", "config": cfg}, format="json")
        self.assertEqual(r.status_code, 200, r.data)

    def test_channel_validation(self):
        for body in (
            {
                "kind": "matrix",
                "config": {"homeserver": "http://m.org", "room_id": "!a:m.org"},
                "secret": "tokentoken",
            },
            {"kind": "telegram", "config": {"chat_id": "abc"}, "secret": TG_TOKEN},
            {"kind": "slack", "config": {}, "secret": "http://hooks.slack.com/x"},
            {"kind": "ntfy", "config": {"topic": "a b"}},
            {"kind": "email", "config": {"recipients": ["nope"]}},
            {"kind": "ntfy", "config": {"topic": "t"}, "quiet_start": "22:00"},
        ):
            r = self.client.post(
                "/notify/channels/", {"name": "x", **body}, format="json"
            )
            self.assertEqual(r.status_code, 400, body)
        self.assertFalse(Channel.objects.exists())

    def test_test_button(self):
        ch = channel()
        with patch(INTERNAL, return_value=False), patch(REQUEST, return_value=ok()):
            r = self.client.post(f"/notify/channels/{ch.pk}/test/")
        self.assertEqual(r.data, {"ok": True, "error": ""})
        with patch(INTERNAL, return_value=False), patch(REQUEST, return_value=ok(401)):
            r = self.client.post(f"/notify/channels/{ch.pk}/test/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data, {"ok": False, "error": "HTTP 401"})
        ch.refresh_from_db()
        self.assertEqual(ch.last_error, "HTTP 401")

    def test_routes_and_history(self):
        ch = channel()
        r = self.client.post(
            "/notify/routes/",
            {
                "name": "all errors",
                "severities": ["error", "error"],
                "sources": ["check", "tamper"],
                "channels": [ch.pk],
                "escalate_after_minutes": 30,
            },
            format="json",
        )
        self.assertEqual(r.status_code, 400)
        self.assertIn("escalate_to", r.data)
        r = self.client.post(
            "/notify/routes/",
            {
                "name": "all errors",
                "severities": ["error", "error"],
                "sources": ["check", "tamper"],
                "channels": [ch.pk],
                "escalate_after_minutes": 30,
                "escalate_to": [ch.pk],
            },
            format="json",
        )
        self.assertEqual(r.status_code, 201, r.data)
        self.assertEqual(r.data["severities"], ["error"])
        r = self.client.post(
            "/notify/routes/", {"name": "x", "sources": ["nope"]}, format="json"
        )
        self.assertEqual(r.status_code, 400)

        baker.make("notify.Notification", channel=ch, source="tamper", title="a")
        baker.make("notify.Notification", channel=ch, source="check", title="b")
        r = self.client.get("/notify/notifications/?source=tamper")
        self.assertEqual([n["title"] for n in r.data], ["a"])
        self.assertEqual(r.data[0]["channel_name"], ch.name)

    def test_permissions(self):
        viewer = self.create_user_with_roles(["can_view_core_settings"])
        self.client.force_authenticate(user=viewer)
        self.assertEqual(self.client.get("/notify/channels/").status_code, 200)
        self.assertEqual(
            self.client.post("/notify/routes/", {"name": "x"}).status_code, 403
        )
        manager = self.create_user_with_roles(["can_manage_notifications"])
        self.client.force_authenticate(user=manager)
        self.assertEqual(
            self.client.post(
                "/notify/routes/", {"name": "x"}, format="json"
            ).status_code,
            201,
        )
        nobody = self.create_user_with_roles([])
        self.client.force_authenticate(user=nobody)
        self.assertEqual(self.client.get("/notify/notifications/").status_code, 403)
        self.check_not_authenticated("get", "/notify/channels/")
