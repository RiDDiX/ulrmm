# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import datetime as dt
import secrets
import string

from cryptography.fernet import InvalidToken
from django.db import transaction
from django.utils import timezone as djangotime
from rest_framework.exceptions import ValidationError

from agents.models import Agent, AgentHistory
from logs.models import DebugLog
from netmon.probe import clean
from remote.utils import decrypt_secret, encrypt_secret
from scripts.models import Script, check_env_vars
from ulrmm.celery import app
from ulrmm.constants import (
    AGENT_DEFER,
    ONLINE_AGENTS,
    AgentHistoryType,
    DebugLogType,
    ScriptType,
)
from ulrmm.utils import redis_lock
from vault.models import HKDF_INFO, Credential

from .models import SCRIPTS, LapsPolicy, LapsState

LAPS_LOCK = "laps-rotate-lock"
# a failed rotation is tried again after this, the notification goes out once
RETRY_AFTER = dt.timedelta(hours=4)
# the script ends before the wait for its answer does
TIMEOUT = 90
WAIT = 120
SYMBOLS = "-_.+@#!"
CLASSES = (string.ascii_lowercase, string.ascii_uppercase, string.digits, SYMBOLS)


def library_script(plat: str) -> "Script | None":
    if plat not in SCRIPTS:
        return None
    return Script.objects.filter(
        filename=SCRIPTS[plat], script_type=ScriptType.BUILT_IN
    ).first()


def new_password(length: int) -> str:
    # every class at least once, Windows complexity rules want three of four
    alphabet = "".join(CLASSES)
    while True:
        password = "".join(secrets.choice(alphabet) for _ in range(length))
        if all(any(c in group for c in password) for group in CLASSES):
            return password


def notify(event: dict) -> None:
    try:
        from notify.dispatch import dispatch
    except ImportError:
        return
    try:
        dispatch(event)
    except Exception as e:
        DebugLog.error(message=f"Notification failed: {clean(e, 200)}")


def _run(agent: Agent, script: Script, env: list[str], username: str) -> dict | str:
    hist = AgentHistory.objects.create(
        agent=agent,
        type=AgentHistoryType.SCRIPT_RUN,
        script=script,
        username=username[:50],
    )
    try:
        return agent.run_script(
            scriptpk=script.pk,
            env_vars=env,
            timeout=TIMEOUT,
            wait_timeout=WAIT,
            full=True,
            wait=True,
            history_pk=hist.pk,
        )
    except Exception as e:
        return clean(e, 200) or type(e).__name__


def _pending(state: LapsState) -> str:
    try:
        return decrypt_secret(state.pending_secret, HKDF_INFO)
    except InvalidToken:
        return ""


def rotate(agent: Agent, username: str = "laps") -> str:
    """Sets a new password with the platform's library script and keeps it
    in the vault. The error, empty on success."""
    policy = LapsPolicy.for_site(agent.site_id)
    if not (policy and policy.enabled):
        return "Local admin rotation is off for this site."
    state, _ = LapsState.objects.get_or_create(agent=agent)
    account = policy.account
    # the device may already have it when the last run got no answer; a changed
    # length or account makes a new one
    pending = _pending(state) if state.pending_secret else ""
    reuse = len(pending) == policy.length and state.pending_account == account
    password = pending if reuse else new_password(policy.length)
    env = [
        f"TARGET_USER={account}",
        f"NEW_PASSWORD={password}",
        f"CREATE_IF_MISSING={str(policy.create_if_missing).lower()}",
    ]

    error = ""
    script = library_script(agent.plat)
    if not script:
        error = "The script library has no rotation script for this platform."
    else:
        try:
            check_env_vars(env, script)
        except ValidationError as e:
            error = f"The library script does not take its variables: {e.detail[0]}"
    if not error:
        state.pending_secret = encrypt_secret(password, HKDF_INFO)
        state.pending_at = (reuse and state.pending_at) or djangotime.now()
        state.pending_account = account
        state.save(update_fields=["pending_secret", "pending_at", "pending_account"])
        r = _run(agent, script, env, username)
        if not isinstance(r, dict):
            error = "The agent did not answer." if r == "timeout" else str(r)
        elif r.get("retcode") != 0:
            out = str(r.get("stderr") or r.get("stdout") or "").strip()
            # the scripts never print it, this is in case one does
            out = out.replace(password, "********")[-200:]
            error = f"The script exited with {r.get('retcode')}: {out}"

    now = djangotime.now()
    if error:
        first = not state.last_error
        state.last_error = clean(error, 500)
        state.next_rotation = now + RETRY_AFTER
        state.save(update_fields=["last_error", "next_rotation"])
        DebugLog.warning(
            agent=agent,
            log_type=DebugLogType.SCRIPTING,
            message=f"Local admin rotation on {agent.hostname} failed: {state.last_error}",
        )
        if first:
            notify(
                {
                    "source": "laps",
                    "severity": "warning",
                    "title": f"Local admin rotation failed on {agent.hostname}",
                    "body": state.last_error,
                    "agent": agent,
                    "dedupe_key": f"laps:{agent.pk}",
                }
            )
        return state.last_error

    # the old credential stays when the account changed
    cred = state.credential
    if not cred or cred.agent_id != agent.pk or cred.username != account:
        cred = Credential(agent=agent)
    cred.name = f"Local admin ({account})"
    cred.username = account
    cred.secret = encrypt_secret(password, HKDF_INFO)
    with transaction.atomic():
        cred.save()
        state.credential = cred
        state.account = account
        state.last_rotation = now
        state.next_rotation = now + dt.timedelta(days=policy.rotate_days)
        state.last_error = ""
        state.pending_secret = ""
        state.pending_at = None
        state.pending_account = ""
        state.save()
    return ""


@app.task
def rotate_agent_task(pk: int, username: str = "laps", force: bool = False) -> str:
    agent = Agent.objects.defer(*AGENT_DEFER).filter(pk=pk).first()
    if not agent:
        return "agent not found"
    with redis_lock(f"laps-rotate-{pk}", rotate_agent_task.app.oid) as acquired:
        if not acquired:
            return "already running"
        due = (
            LapsState.objects.filter(agent=agent)
            .values_list("next_rotation", flat=True)
            .first()
        )
        if not force and due and due > djangotime.now():
            return "not due"
        return rotate(agent, username) or "ok"


@app.task(bind=True)
def laps_rotate_task(self) -> str:
    with redis_lock(LAPS_LOCK, self.app.oid) as acquired:
        if not acquired:
            return f"{self.app.oid} still running"

        policies = {p.site_id: p for p in LapsPolicy.objects.all()}
        default = policies.get(None)
        due = dict(LapsState.objects.values_list("agent_id", "next_rotation"))
        now = djangotime.now()
        queued = 0
        agents = Agent.objects.filter(plat__in=list(SCRIPTS)).only(
            *ONLINE_AGENTS, "site"
        )
        for agent in agents:
            policy = policies.get(agent.site_id, default)
            if not (policy and policy.enabled) or not agent.is_online:
                continue
            when = due.get(agent.pk)
            if when is None or when <= now:
                rotate_agent_task.delay(agent.pk)
                queued += 1
        return f"{queued} queued"
