"""Golden API tests.

Every item of items/<area>.json runs as its own test against the seeded fixture
(fixtures/golden_seed.json) and its masked answer is compared with
data/<area>.json. GOLDEN_RECORD=1 writes the answers of the current tree instead:

    GHACTIONS=yes GOLDEN_RECORD=1 pytest -p no:cacheprovider -q ulrmm/golden
"""

import contextlib
import difflib
import fnmatch
import hashlib
import io
import json
import os
import re
import sys
import time
import traceback
import unittest
import urllib.error
import urllib.request
import urllib.response
from datetime import datetime, timedelta, timezone
from email.message import Message
from pathlib import Path
from unittest import mock
from urllib.parse import urlsplit

import pyotp
import time_machine
from django.apps import apps
from django.conf import settings
from django.core.cache import cache
from django.core.cache.backends.locmem import LocMemCache
from django.core.management.color import no_style
from django.core.management.commands import shell as shell_command
from django.db import (
    DEFAULT_DB_ALIAS,
    DatabaseError,
    connection,
    connections,
    transaction,
)
from django.test import Client, TestCase, override_settings

HERE = Path(__file__).resolve().parent
FIXTURE = str(HERE.parent / "fixtures" / "golden_seed.json")
RECORD = os.environ.get("GOLDEN_RECORD") == "1"

# the fixture carries absolute dates (expiries, last_seen): every test starts here
NOW = datetime(2026, 10, 18, 6, 0, tzinfo=timezone.utc)
# the items were written for a server on this port, recorded as side "new"
PORT = "8002"
SIDE = "new"
DEFAULT_TOTP = "JBSWY3DPEHPK3PXP"
HDRS = ("content-type", "content-disposition", "location", "www-authenticate", "allow")
USER_AGENT = "Python-urllib/%d.%d" % sys.version_info[:2]

DASHBOARD_USERS = (
    "admin",
    "clienta",
    "site",
    "readonly",
    "installer",
    "rolesuper",
    "noperm",
    "acctmgr",
    "blocked",
    "inactive",
    "sso",
    "nototp",
)
API_KEYS = ("expired", "far", "null", "installer", "inactive")
DEPLOYMENTS = {
    "deploy_bremen_ws": 13,
    "deploy_main_office_srv_expired": 14,
    "deploy_unreached_arm": 15,
}
AGENTS = (1, 9, 17)

MASKS = [
    (
        re.compile(r"\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(\.\d+)?(Z|[+-]\d\d:?\d\d)?"),
        "<TS>",
    ),
    (
        re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
        "<UUID>",
    ),
    (re.compile(r"(ULRMM_SchedReboot_)[A-Za-z]{10}"), r"\1<rnd>"),
    (re.compile(r"\x1b\[[0-9;]*m"), ""),
]
DBSPEC = re.compile(r"^\s*(\w+)\s*(?:\(([^)]*)\))?\s*(?:where\s+(.*))?$", re.I | re.S)

# a redis database of its own for the celery queue, apart from other test runs
BROKER_DB = 13

_real_urlopen = urllib.request.urlopen


def use_broker(url):
    from ulrmm.celery import app

    old = app.conf.broker_url
    app.conf.broker_url = url
    app._pool = None
    if "amqp" in app.__dict__:
        app.__dict__["amqp"]._producer_pool = None
    return old


def clear_queue():
    from ulrmm.celery import app

    with app.connection_for_write() as c:
        c.default_channel.client.delete("celery")


class GoldenCache(LocMemCache):
    """Process-local cache with the pattern helpers of the redis backend."""

    def iter_keys_pattern(self, pattern, version=None):
        match = f":{version or 1}:{pattern}"
        with self._lock:
            keys = [k for k in self._cache if fnmatch.fnmatchcase(k, match)]
        return iter([k.encode() for k in keys if not self._has_expired(k)])

    def delete_many_pattern(self, pattern, version=None):
        for key in list(self.iter_keys_pattern(pattern, version)):
            with self._lock:
                self._delete(key.decode())

    def show_everything(self, version=None):
        return list(self.iter_keys_pattern("*", version=version))

    def raw_ttl(self, key):
        if isinstance(key, bytes):
            key = key.decode()
        with self._lock:
            if key not in self._cache or self._has_expired(key):
                return -2
            exp = self._expire_info.get(key)
        return -1 if exp is None else int(exp - time.time())


@contextlib.contextmanager
def quiet_fds():
    # programs started by a shell item write to fd 1/2 directly (the qr tool draws a
    # PNG of a random key); that output is not part of the answer
    saved = [os.dup(1), os.dup(2)]
    null = os.open(os.devnull, os.O_WRONLY)
    try:
        os.dup2(null, 1)
        os.dup2(null, 2)
        yield
    finally:
        os.dup2(saved[0], 1)
        os.dup2(saved[1], 2)
        for fd in saved + [null]:
            os.close(fd)


def apply_masks(text, masks):
    for rx, rep in MASKS:
        text = rx.sub(rep, text)
    for m in masks:
        text = re.sub(m, "<X>", text)
    return text


def _sorted(o):
    if isinstance(o, dict):
        return {k: _sorted(v) for k, v in o.items()}
    if isinstance(o, list):
        return sorted(
            (_sorted(v) for v in o), key=lambda v: json.dumps(v, sort_keys=True)
        )
    return o


def _render(rec):
    out = [f"#status {rec.get('status')}", rec.get("body_masked", "")]
    for h, v in (rec.get("headers") or {}).items():
        out.append(f"#header {h}: {v}")
    for spec, v in (rec.get("db_masked") or {}).items():
        out += [f"#db {spec}", v]
    return "\n".join(out).splitlines()


@override_settings(
    CACHES={
        "default": {"BACKEND": "ulrmm.golden.base.GoldenCache", "LOCATION": "golden"}
    }
)
class GoldenCase(TestCase):
    area = ""
    fixtures = [FIXTURE]

    @classmethod
    def setUpClass(cls):
        # loading the fixture builds every row, and load hooks such as the
        # one that completes scheduled reboots whose time passed must see
        # the bench time, not the real one
        with time_machine.travel(NOW, tick=False):
            super().setUpClass()
        cls.broker = use_broker(f"{settings.REDIS_URL}/{BROKER_DB}")
        cls.golden_path = HERE / "data" / f"{cls.area}.json"
        try:
            cls.golden = json.loads(cls.golden_path.read_text())
        except FileNotFoundError:
            cls.golden = {}
        cls.recorded = {}
        models = [
            m
            for m in apps.get_models(include_auto_created=True)
            if m._meta.managed and not m._meta.proxy
        ]
        # sequences are not transactional: every test starts from the fixture's values
        cls.reset_sql = "\n".join(connection.ops.sequence_reset_sql(no_style(), models))

    @classmethod
    def tearDownClass(cls):
        if RECORD and cls.recorded:
            data = {**cls.golden, **cls.recorded}
            cls.golden_path.write_text(
                json.dumps(dict(sorted(data.items())), indent=1, ensure_ascii=False)
                + "\n"
            )
        use_broker(cls.broker)
        super().tearDownClass()

    @classmethod
    def setUpTestData(cls):
        from clients.models import Deployment
        from knox.models import AuthToken
        from rest_framework.authtoken.models import Token

        # dashboard sessions end 12 h after login; the seed's tokens are older
        AuthToken.objects.update(created=NOW - timedelta(hours=1))
        tok = {
            k: hashlib.sha256(f"golden-{k}".encode()).hexdigest()
            for k in DASHBOARD_USERS
        }
        tok.update(
            {f"apikey_{k}": f"BENCHAPIKEY{k.upper()}".ljust(32, "K") for k in API_KEYS}
        )
        tok.update(
            {
                k: Deployment.objects.get(pk=pk).token_key
                for k, pk in DEPLOYMENTS.items()
            }
        )
        cls.tokens = tok
        cls.agent_tokens = {
            str(pk): Token.objects.get(user__agent_id=pk).key for pk in AGENTS
        }

    def setUp(self):
        traveller = time_machine.travel(NOW, tick=True)
        self.clock = traveller.start()
        self.addCleanup(traveller.stop)
        cache.clear()
        clear_queue()
        with connection.cursor() as c:
            c.execute(self.reset_sql)
        self.client = Client(enforce_csrf_checks=True, raise_request_exception=False)
        # an atomic block that is the outermost one on the server checks deferred
        # foreign keys when it ends, as its commit would
        self.server_depth = len(connection.savepoint_ids)
        conn = connections[DEFAULT_DB_ALIAS]
        release = conn.savepoint_commit

        def savepoint_commit(sid):
            if len(conn.savepoint_ids) == self.server_depth:
                self.check_deferred()
            release(sid)

        patcher = mock.patch.object(conn, "savepoint_commit", savepoint_commit)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.totp_used = set()
        self.totp_last = "000000"
        self.rolled_back = []

    def totp(self, secret):
        # a code is single use, so the next one for a secret waits for a new window
        if (secret, int(time.time() // 30)) in self.totp_used:
            self.clock.shift(30.5 - time.time() % 30)
        self.totp_used.add((secret, int(time.time() // 30)))
        self.totp_last = pyotp.TOTP(secret).now()
        return self.totp_last

    def sub(self, o):
        if isinstance(o, list):
            return [self.sub(x) for x in o]
        if isinstance(o, dict):
            return {k: self.sub(v) for k, v in o.items()}
        if not isinstance(o, str):
            return o
        s = o.replace("{{PORT}}", PORT).replace("{{SIDE}}", SIDE)
        s = re.sub(r"\{\{TOKEN:(\w+)\}\}", lambda m: self.tokens[m.group(1)], s)
        s = re.sub(
            r"\{\{AGENT_TOKEN:(\d+)\}\}", lambda m: self.agent_tokens[m.group(1)], s
        )
        s = s.replace("{{TOTP_LAST}}", self.totp_last)
        return re.sub(
            r"\{\{TOTP(?::(\w+))?\}\}",
            lambda m: self.totp(m.group(1) or DEFAULT_TOTP),
            s,
        )

    def auth_headers(self, token):
        if not token or token == "none":
            return {}
        if token.startswith("agent:"):
            return {"Authorization": "Token " + self.agent_tokens[token[6:]]}
        if token.startswith("apikey_"):
            return {"X-API-KEY": self.tokens[token]}
        return {"Authorization": "Token " + self.tokens[token]}

    def check_deferred(self):
        with connection.cursor() as c:
            c.execute("SET CONSTRAINTS ALL IMMEDIATE")
            c.execute("SET CONSTRAINTS ALL DEFERRED")

    @contextlib.contextmanager
    def guard(self):
        # outside a test every request and shell run commits on its own
        sid = transaction.savepoint()
        try:
            with self.captureOnCommitCallbacks(execute=True):
                yield
        finally:
            try:
                self.check_deferred()
                transaction.savepoint_commit(sid)
            except DatabaseError as e:
                # the server would not have kept these writes
                transaction.savepoint_rollback(sid)
                self.rolled_back.append(str(e).splitlines()[0])

    def http(self, method, path, headers, body):
        # as urllib sends it: capitalized names, the last one wins, data is a form
        hdr = {}
        for k, v in headers.items():
            hdr[k.capitalize()] = v
        if body is not None:
            hdr.setdefault("Content-type", "application/x-www-form-urlencoded")
        hdr.setdefault("User-agent", USER_AGENT)
        ctype = hdr.pop("Content-type", None)
        with self.guard():
            r = self.client.generic(
                method,
                path,
                data=body or b"",
                content_type=ctype or "application/octet-stream",
                headers=hdr,
            )
        content = b"".join(r.streaming_content) if r.streaming else r.content
        return r.status_code, {k.lower(): v for k, v in r.items()}, content

    def urlopen(self, req, data=None, timeout=None, **kw):
        # shell items talk to the bench server on {{PORT}}: answer them in-process
        if isinstance(req, str):
            req = urllib.request.Request(req, data)
        u = urlsplit(req.full_url)
        if u.netloc != f"localhost:{PORT}":
            return _real_urlopen(req, data, timeout, **kw)
        status, headers, body = self.http(
            req.get_method(),
            u.path + ("?" + u.query if u.query else ""),
            dict(req.header_items()),
            req.data,
        )
        msg = Message()
        for k, v in headers.items():
            msg[k] = v
        if status >= 400:
            raise urllib.error.HTTPError(
                req.full_url, status, "", msg, io.BytesIO(body)
            )
        return urllib.response.addinfourl(io.BytesIO(body), msg, req.full_url, status)

    def shell(self, code):
        from ulrmm.middleware import request_local

        # like manage.py shell: its module globals, exit code 1 on an exception
        ns = dict(vars(shell_command))
        out, err = io.StringIO(), io.StringIO()
        status = 0
        with quiet_fds(), contextlib.redirect_stdout(out):
            with contextlib.redirect_stderr(err), self.guard():
                with mock.patch("urllib.request.urlopen", self.urlopen):
                    try:
                        exec(compile(code, "<shell>", "exec"), ns)
                    except SystemExit as e:
                        status = (
                            e.code if isinstance(e.code, int) else int(bool(e.code))
                        )
                    except Exception:
                        traceback.print_exc()
                        status = 1
        request_local.__dict__.clear()
        return status, out.getvalue(), err.getvalue()

    def db_snapshot(self, specs):
        out = {}
        for spec in specs:
            m = DBSPEC.match(spec)
            if not m:
                out[spec] = "BAD DB SPEC"
                continue
            t, cols, where = m.groups()
            cond = f" where {where}" if where else ""
            sel = f"(select {cols or '*'} from {t} x0{cond})"
            q = (
                "select coalesce(json_agg(r order by r::text), '[]') from "
                f"(select to_jsonb(x) as r from {sel} x) y"
            )
            try:
                with self.guard(), connection.cursor() as c:
                    c.execute(q)
                    out[spec] = c.fetchone()[0]
            except DatabaseError as e:
                out[spec] = "PSQLERR " + str(e).strip()[:300]
        return out

    def execute(self, it):
        if it.get("setup"):
            self.shell(self.sub(it["setup"]))
        if it.get("method", "GET").upper() == "SHELL":
            status, text, _ = self.shell(self.sub(it["shell"]))
            headers = {}
        else:
            headers = {
                **self.auth_headers(it.get("token")),
                **self.sub(it.get("headers") or {}),
            }
            body = it.get("body")
            if body is not None:
                body = self.sub(body)
                if isinstance(body, str) and it.get("raw_body"):
                    body = body.encode()
                else:
                    body = json.dumps(body).encode()
                    headers.setdefault("Content-Type", "application/json")
            status, headers, raw = self.http(
                it["method"].upper(), self.sub(it["path"]), headers, body
            )
            text = raw.decode("utf-8", "replace")
        c = it.get("compare") or {}
        masks = c.get("mask") or []
        kind = c.get("body", "json")
        if kind == "ignore":
            text = ""
        elif kind == "json":
            try:
                parsed = json.loads(text)
                if it.get("unordered"):
                    parsed = _sorted(parsed)
                text = json.dumps(parsed, indent=1, sort_keys=True, ensure_ascii=False)
            except ValueError:
                text = "NOT JSON: " + text
        rec = {
            "status": status if c.get("status", True) else None,
            "body_masked": apply_masks(text, masks),
        }
        if c.get("headers"):
            rec["headers"] = {h: headers.get(h) for h in c["headers"]}
        if self.rolled_back:
            rec["rolled_back"], self.rolled_back = self.rolled_back, []
        if c.get("db"):
            snap = self.db_snapshot(c["db"])
            rec["db_masked"] = {
                spec: apply_masks(
                    json.dumps(
                        _sorted(snap[spec]) if it.get("unordered") else snap[spec],
                        indent=1,
                        sort_keys=True,
                        ensure_ascii=False,
                    ),
                    masks,
                )
                for spec in c["db"]
            }
        return rec

    def check(self, it, chain):
        for before in chain:
            self.execute(before)
        rec = self.execute(it)
        if RECORD:
            type(self).recorded[it["id"]] = rec
            return
        want = self.golden.get(it["id"])
        if want is None:
            self.fail(f"{it['id']}: no golden answer, record with GOLDEN_RECORD=1")
        if rec != want:
            diff = difflib.unified_diff(
                _render(want), _render(rec), "golden", "now", lineterm="", n=2
            )
            self.fail(f"{it['id']}: {it.get('desc', '')}\n" + "\n".join(diff))


def chain_for(items, n):
    """Items that run before item n in its test, because it inspects what they left."""
    it = items[n]
    if "{{TOTP_LAST}}" in json.dumps(it):
        # replays the code its predecessor used
        return items[n - 1 : n]
    if "lrange('celery'" in (it.get("shell") or ""):
        # reads the queue filled since the queue was last emptied or the bench reset
        start = n - 1
        while start > 0:
            prev = items[start]
            text = (prev.get("setup") or "") + (prev.get("shell") or "")
            if prev.get("reset_before") or "delete('celery')" in text:
                break
            start -= 1
        return items[start:n]
    return []


def add_items(case):
    items = json.loads((HERE / "items" / f"{case.area}.json").read_text())
    for n, it in enumerate(items):

        def test(self, it=it, chain=chain_for(items, n)):
            self.check(it, chain)

        test.__doc__ = it.get("desc")
        name = "test_" + it["id"].replace("-", "_")
        test.__name__ = name
        if it.get("skip"):
            test = unittest.skip(it["skip"])(test)
        setattr(case, name, test)
    return case
