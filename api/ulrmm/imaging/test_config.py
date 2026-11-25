# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import hashlib
import json
from pathlib import Path

from model_bakery import baker

from . import resolver
from .models import Profile
from .native import CONFIG_HEADER
from .service import backup_rows
from .test_poll import PollBase

VECTORS = Path(__file__).parent / "testdata" / "config_vectors.json"


class TestConfigDocument(PollBase):
    def ack(self, status="applied", version=None, digest=None, errors=()):
        state = self.state()
        return self.poll(
            protocol=2,
            config={
                "version": state.config_version if version is None else version,
                "hash": state.config_hash if digest is None else digest,
                "status": status,
                "errors": list(errors),
            },
        )

    def sync(self):
        return self.client.get(self.uri).data["sync"]

    def test_canonical_bytes_and_hash(self):
        doc = {"b": [1, {"ä": True}], "a": None}
        raw = resolver.canonical(doc)
        self.assertEqual(raw, '{"a":null,"b":[1,{"ä":true}]}'.encode())
        self.assertEqual(resolver.digest(doc), hashlib.sha256(raw).hexdigest())
        state = self.state()
        self.assertEqual(
            hashlib.sha256(state.config_doc.encode()).hexdigest(), state.config_hash
        )

    def test_config_vectors_file(self):
        vectors = json.loads(VECTORS.read_text(encoding="utf-8"))
        self.assertGreaterEqual(len(vectors), 4)
        for vector in vectors:
            raw = resolver.canonical(vector["document"])
            self.assertEqual(raw.decode("utf-8"), vector["canonical"])
            self.assertEqual(hashlib.sha256(raw).hexdigest(), vector["sha256"])
        defaults = vectors[0]["document"]
        rendered = json.loads(self.state().config_doc)
        self.assertEqual(
            {k: v for k, v in rendered.items() if k not in ("agent_id", "target")},
            {k: v for k, v in defaults.items() if k not in ("agent_id", "target")},
        )

    def test_no_secret_no_float_in_document(self):
        script = baker.make(
            "scripts.Script", name="Dump", shell="powershell", script_body="x"
        )
        hooks = [
            {
                "script_id": script.pk,
                "phase": "pre-backup",
                "args": ["--all"],
                "env_vars": ["PGPASS=hunter2"],
                "timeout": 60,
                "on_fail": "abort",
            }
        ]
        profile, _ = backup_rows(self.agent)
        Profile.objects.filter(pk=profile.pk).update(overrides={"hooks": hooks})
        _, state = resolver.resolve_device(self.agent, cause="device")
        self.assertNotIn("hunter2", state.config_doc)
        self.assertNotIn("--all", state.config_doc)

        def walk(value):
            self.assertNotIsInstance(value, float)
            for item in (
                value.values()
                if isinstance(value, dict)
                else (value if isinstance(value, list) else ())
            ):
                walk(item)

        walk(json.loads(state.config_doc))
        # hooks travel only in the sealed claim
        self.assertEqual(json.loads(state.config_doc)["hooks"], [])

    def test_header_on_200_and_204(self):
        r = self.poll()
        self.assertEqual(r.status_code, 204)
        self.assertEqual(r[CONFIG_HEADER], str(self.state().config_version))
        self.assertGreaterEqual(self.state().config_version, 1)
        self.queue()
        r = self.poll()
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r[CONFIG_HEADER], str(self.state().config_version))
        r = self.worker.post(self.url, {"capability": {}}, format="json", secure=True)
        self.assertEqual(r.status_code, 400)
        self.assertFalse(r.has_header(CONFIG_HEADER))

    def test_config_get_sealed_only(self):
        url = self.url + "config/"
        r = self.worker.get(url, secure=True)
        self.assertEqual(r.status_code, 403)
        self.assertEqual(
            r.data,
            {
                "detail": "Backup settings are sent only on a sealed channel.",
                "check": "agent.sealing",
            },
        )
        self.identity()
        self.assertEqual(self.worker.get(url, secure=True).status_code, 403)
        r = self.worker.get(url, secure=True, HTTP_X_ULRMM_SEAL="1")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r["X-ULRMM-Sealed"], "1")
        self.assertEqual(r[CONFIG_HEADER], str(self.state().config_version))
        self.assertEqual(self.worker.get(url).status_code, 403)

    def test_ack_synced_pending_error_legacy(self):
        self.assertEqual(self.sync()["state"], "legacy")
        self.ack(status="none", version=0, digest="")
        self.assertEqual(self.sync()["state"], "pending")
        self.ack()
        sync = self.sync()
        self.assertEqual(sync["state"], "synced")
        self.assertIsNone(sync["pending_since"])
        errors = [
            {
                "field": "network_mode",
                "message": "Internal-only mode is not usable here.",
            }
        ]
        self.ack(status="error", digest="a" * 64, errors=errors)
        sync = self.sync()
        self.assertEqual((sync["state"], sync["errors"]), ("error", errors))
        self.assertIn("config_error", self.state().alerts)
        self.ack()
        self.assertEqual(self.sync()["state"], "synced")
        self.assertNotIn("config_error", self.state().alerts)
        # an acknowledgement of another version changes nothing
        Profile.objects.filter(agent=self.agent).update(overrides={"smart": "off"})
        resolver.resolve_device(self.agent, cause="device")
        self.ack(version=1)
        self.assertEqual(self.sync()["state"], "pending")

    def test_error_ack_sets_acked_version_and_time(self):
        state = self.state()
        self.ack(
            status="error", digest="b" * 64, errors=[{"field": "x", "message": "y"}]
        )
        acked = self.state()
        self.assertEqual(acked.acked_version, state.config_version)
        self.assertEqual(acked.acked_hash, "b" * 64)
        self.assertEqual(acked.ack_status, "error")
        self.assertIsNotNone(acked.acked_at)

    def test_protocol_above_2_treated_as_2(self):
        self.assertEqual(self.poll(protocol=7).status_code, 204)
        self.assertEqual(self.state().protocol, 2)
        self.assertEqual(self.poll(protocol=1).status_code, 400)
