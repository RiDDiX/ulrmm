# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import importlib
import json
from unittest.mock import patch

import requests
from django.core.cache import cache
from django.test import SimpleTestCase, override_settings
from django.utils import timezone as djangotime
from model_bakery import baker

from logs.models import DebugLog
from ulrmm.constants import REDIS_LOCK_EXPIRE
from ulrmm.test import LOCMEM_CACHE, ULRMMTestCase
from ulrmm.utils import redis_lock

from . import link, removal
from .models import ImportedDevice, ImportSource
from .sources.base import NoAnswer, NotFound, Refused, Source
from .sources.ninjaone import NinjaOne
from .sources.upstream import Upstream
from .tasks import REMOVE_LOCK, fetch, remove_task
from .tests import BASE, FakeRemote, _source, _wmi

KEY = "k3y-“pasted"


def _response(status, body=b""):
    r = requests.Response()
    r.status_code, r._content, r._content_consumed = status, body, True
    return r


class TestSources(SimpleTestCase):
    def test_call_stays_on_the_base(self):
        src = Source("https://old", True, {}, {})
        with patch.object(src.session, "request", return_value=_response(204)) as r:
            src.call("GET", "https://evil/x")
        self.assertEqual(r.call_args.args[1], "https://oldhttps://evil/x")

    def test_server_errors_are_no_answer(self):
        src = Source("https://old", True, {}, {})
        for status, error in (
            (500, NoAnswer),
            (503, NoAnswer),
            (401, Refused),
            (403, Refused),
        ):
            with self.subTest(status):
                with patch.object(
                    src.session, "request", return_value=_response(status)
                ):
                    with self.assertRaises(error):
                        src.call("GET", "/x/")

    def test_unexpected_removal_answer_is_no_answer(self):
        src = Upstream("https://old", True, {}, {"api_key": "k"})
        for body in (b'"done"', b"[]"):
            with self.subTest(body):
                with patch.object(
                    src.session, "request", return_value=_response(200, body)
                ):
                    with self.assertRaises(NoAnswer):
                        src.remove("AGENT1", "WS01")

    def test_ninjaone_values_swallow_only_hidden_fields(self):
        src = NinjaOne("https://eu.ninjarmm.com", True, {"client_id": "C"}, {})
        for error in (NotFound("404"), Refused("403")):
            with patch.object(Source, "call", side_effect=error):
                self.assertEqual(src._values("/v2/x", {}, {}), {})
        with patch.object(Source, "call", side_effect=NoAnswer("timeout")):
            with self.assertRaises(NoAnswer):
                src._values("/v2/x", {}, {})

    def test_real_serial(self):
        self.assertEqual(link.real_serial(" CZC1234XYZ "), "czc1234xyz")
        for value in (None, "", "1234", "AAAAAAAA", "To Be Filled By O.E.M."):
            self.assertEqual(link.real_serial(value), "", value)


@override_settings(CACHES=LOCMEM_CACHE)
class TestViews(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()

    def test_secret_must_be_ascii(self):
        body = {"kind": "upstream", "name": "old", "url": "https://old.example.com"}
        r = self.client.post(
            f"{BASE}/", {**body, "secrets": {"api_key": KEY}}, format="json"
        )
        self.assertEqual(r.status_code, 400)
        self.assertIn("plain ASCII", str(r.data["secrets"]))
        self.assertFalse(ImportSource.objects.exists())

    def test_import_lock_outlives_the_request_only_briefly(self):
        src = _source()
        with (
            patch("importers.views.redis_lock", wraps=redis_lock) as lock,
            patch("importers.views.engine.run", return_value={}),
        ):
            r = self.client.post(
                f"{BASE}/{src.pk}/import/", {"parts": ["clients"]}, format="json"
            )
        self.assertEqual(r.status_code, 200, r.data)
        self.assertEqual(lock.call_args.kwargs["ttl"], 330)

    def test_request_lock_reads_the_harakiri(self):
        from . import views

        try:
            for value, ttl in (("120", 150), (0, REDIS_LOCK_EXPIRE)):
                with self.subTest(value), self.settings(UWSGI_HARAKIRI=value):
                    self.assertEqual(importlib.reload(views).REQUEST_LOCK, ttl)
        finally:
            importlib.reload(views)

    def test_unexpected_fetch_error_logs_only_the_type(self):
        src = baker.make(ImportSource, kind="upstream", url="https://o")
        error = UnicodeEncodeError("latin-1", KEY, 4, 5, "not in range")
        with patch("importers.tasks.for_source", side_effect=error):
            fetch(src)
        logged = " ".join(DebugLog.objects.values_list("message", flat=True))
        self.assertIn("UnicodeEncodeError", logged)
        self.assertNotIn("pasted", logged)


class TestRemovalRounds(ULRMMTestCase):
    def setUp(self):
        self.authenticate()
        self.setup_coresettings()
        self.src = baker.make(
            ImportSource, kind="upstream", name="old", url="https://o"
        )
        now = djangotime.now()
        self.agent = baker.make(
            "agents.Agent",
            hostname="WS01",
            plat="windows",
            last_seen=now,
            public_ip="203.0.113.10",
            wmi_detail=_wmi("CZC1234XYZ", ["172.17.9.121", "172.17.9.6"]),
        )
        self.device = ImportedDevice.objects.create(
            source=self.src,
            ref="AGENT1",
            hostname="ws01.acme.local",
            serial="CZC1234XYZ",
            plat="windows",
            agent=self.agent,
            sent_at=now - djangotime.timedelta(hours=1),
        )
        removal.request(self.src, [self.device.pk], "john")
        self.detail = {
            "hostname": "WS01",
            "plat": "windows",
            "status": "online",
            "public_ip": "203.0.113.10",
            "local_ips": "172.17.9.121, 172.17.9.6",
            "wmi_detail": _wmi("CZC1234XYZ", ["172.17.9.121", "172.17.9.6"]),
        }
        self.remote = FakeRemote(self.detail)

    def row(self):
        return ImportedDevice.objects.select_related("source").get(pk=self.device.pk)

    def test_clone_with_other_serial_is_refused(self):
        detail = {**self.detail, "wmi_detail": _wmi("CZC9999ABC", [])}
        self.assertEqual(
            removal.same_machine(detail, self.agent, self.row()),
            "the serial numbers differ on both sides",
        )

    def test_server_error_then_gone_is_removed(self):
        client = Upstream("https://o", True, {}, {"api_key": "k"})
        gets = iter([_response(200, json.dumps(self.detail).encode()), _response(404)])

        def answer(method, url, **kw):
            return _response(502) if method == "DELETE" else next(gets)

        with patch.object(client.session, "request", side_effect=answer):
            self.assertEqual(removal.step(self.row(), client), "waiting_there")
            self.assertTrue(self.row().remove_tried_at)
            self.assertEqual(removal.step(self.row(), client), "removed")
        self.assertEqual(self.row().recovery, "pending")

    def test_a_stale_row_sees_the_other_rounds_call(self):
        stale = self.row()
        self.remote.answer_error = NoAnswer("/agents/AGENT1/: ReadTimeout")
        self.assertEqual(removal.step(self.row(), self.remote), "waiting_there")
        self.remote.detail_error = NotFound("404")
        self.assertEqual(removal.step(stale, self.remote), "removed")
        self.assertEqual(self.row().recovery, "pending")

    def test_a_stale_row_never_expires_a_tried_device(self):
        now = djangotime.now()
        ImportedDevice.objects.filter(pk=self.device.pk).update(
            remove_requested_at=now - djangotime.timedelta(days=8)
        )
        stale = self.row()
        ImportedDevice.objects.filter(pk=self.device.pk).update(
            remove_state="waiting_there", remove_tried_at=now
        )
        removal.step(stale, self.remote)
        self.assertEqual(self.row().remove_state, "waiting_there")
        self.remote.detail_error = NotFound("404")
        self.assertEqual(removal.step(self.row(), self.remote), "removed")

    def test_unexpected_error_logs_only_the_type(self):
        self.remote.detail_error = ValueError(KEY)
        removal.step(self.row(), self.remote)
        logged = " ".join(DebugLog.objects.values_list("message", flat=True))
        self.assertIn("ValueError", logged)
        self.assertNotIn("pasted", logged)

    @override_settings(CACHES=LOCMEM_CACHE)
    def test_repair_never_waits_for_a_round(self):
        cache.add(REMOVE_LOCK, "killed worker")
        try:
            with (
                patch("importers.tasks.removal.recover_due", return_value=[7]),
                patch("importers.tasks.recover_task.delay") as delay,
            ):
                self.assertEqual(remove_task(), "busy")
        finally:
            cache.delete(REMOVE_LOCK)
        delay.assert_called_once_with(7)

    @override_settings(CACHES=LOCMEM_CACHE)
    def test_rounds_never_stack(self):
        cache.add(REMOVE_LOCK, "other worker")
        try:
            self.assertEqual(remove_task(), "busy")
        finally:
            cache.delete(REMOVE_LOCK)
        self.assertEqual(self.row().remove_state, "waiting_here")
