# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import datetime as dt
import re
from time import sleep
from typing import Optional

from django.conf import settings
from django.core.management import call_command
from django.utils import timezone as djangotime

from agents.models import Agent, AgentHistory
from alerts.models import Alert
from core.utils import get_core_settings
from logs.models import DebugLog
from scripts.models import Script
from ulrmm.celery import app
from ulrmm.constants import AGENT_DEFER, AGENT_OUTAGES_LOCK, AGENT_STATUS_OVERDUE
from ulrmm.constants import CheckStatus, DebugLogType
from ulrmm.helpers import rand_range
from ulrmm.logger import logger
from ulrmm.utils import redis_lock

# header values come from agent data; a line break would end the header
_HEADER_UNSAFE = re.compile(r"[\x00-\x1f\x7f]+")

# per-agent alert flags reset when old faults are cleared
_OVERDUE_FLAGS = (
    "overdue_email_alert",
    "overdue_text_alert",
    "overdue_dashboard_alert",
)


@app.task
def send_agent_update_task(*, agent_ids: list[str], force: bool) -> None:
    agents = (
        Agent.objects.defer(*AGENT_DEFER).filter(agent_id__in=agent_ids).order_by("pk")
    )
    for agent in agents:
        agent.do_update(force=force)


@app.task
def auto_self_agent_update_task() -> None:
    if getattr(settings, "ULRMM_DISABLE_AGENT_AUTO_UPDATE_TASK", False):
        return
    call_command("update_agents")


def _notify(pk: int, field: str, send: str, alert_interval=None) -> str:
    """Sends one agent availability notification unless it went out already.

    The stamp is claimed on the alert first, so two workers never both send;
    a failed send hands it back for the next run.
    """
    alert = Alert.objects.select_related("agent").filter(pk=pk).first()
    if alert is None or alert.agent is None:
        return "alert not found"

    previous = getattr(alert, field)
    stamp = Alert.claim_notification(pk, field, alert_interval)
    if stamp is None:
        return "ok"

    # spread a burst of notifications out a little
    sleep(rand_range(100, 1500))
    try:
        getattr(alert.agent, send)()
    except Exception:
        Alert.release_notification(pk, field, stamp, previous)
        raise
    return "ok"


@app.task
def agent_outage_email_task(pk: int, alert_interval: Optional[float] = None) -> str:
    return _notify(pk, "email_sent", "send_outage_email", alert_interval)


@app.task
def agent_recovery_email_task(pk: int) -> str:
    return _notify(pk, "resolved_email_sent", "send_recovery_email")


@app.task
def agent_outage_sms_task(pk: int, alert_interval: Optional[float] = None) -> str:
    return _notify(pk, "sms_sent", "send_outage_sms", alert_interval)


@app.task
def agent_recovery_sms_task(pk: int) -> str:
    return _notify(pk, "resolved_sms_sent", "send_recovery_sms")


@app.task(bind=True)
def agent_outages_task(self) -> str:
    from core.tasks import _get_agent_qs

    with redis_lock(AGENT_OUTAGES_LOCK, self.app.oid) as got_lock:
        if not got_lock:
            return f"{self.app.oid} still running"
        overdue = (a for a in _get_agent_qs() if a.status == AGENT_STATUS_OVERDUE)
        for agent in overdue:
            Alert.handle_alert_failure(agent)
    return "completed"


def _results_mail(agent: Agent, script: Script, result: dict) -> tuple[str, str]:
    subject = _HEADER_UNSAFE.sub(
        " ",
        f"{agent.client.name}, {agent.site.name}, {agent.hostname} {script.name} Results",
    )
    try:
        seconds = f"{float(result.get('execution_time', 0)):.4f}"
    except (TypeError, ValueError):
        seconds = str(result.get("execution_time"))
    body = (
        f"{subject}\n"
        f"Return code: {result.get('retcode')}\n"
        f"Execution time: {seconds} seconds\n"
        f"Stdout: {result.get('stdout')}\n"
        f"Stderr: {result.get('stderr')}"
    )
    return subject, body


@app.task
def run_script_email_results_task(
    agentpk: int,
    scriptpk: int,
    nats_timeout: int,
    emails: Optional[list[str]],
    args: list[str] = [],
    history_pk: int = 0,
    run_as_user: bool = False,
    env_vars: list[str] = [],
) -> None:
    agent = Agent.objects.select_related("site__client").filter(pk=agentpk).first()
    script = Script.objects.filter(pk=scriptpk).first()
    if agent is None or script is None:
        return

    result = agent.run_script(
        scriptpk=scriptpk,
        args=args,
        full=True,
        timeout=nats_timeout,
        wait=True,
        history_pk=history_pk,
        run_as_user=run_as_user,
        env_vars=env_vars,
    )
    if result == "timeout":
        DebugLog.error(
            agent=agent,
            log_type=DebugLogType.SCRIPTING,
            message=f"{agent.hostname}({agent.pk}) timed out running script.",
        )
        return
    if not isinstance(result, dict):
        DebugLog.error(
            agent=agent,
            log_type=DebugLogType.SCRIPTING,
            message=f"{agent.hostname}({agent.pk}) returned no script result: {result}",
        )
        return

    subject, body = _results_mail(agent, script, result)
    # send_mail checks the certificate, falls back to the alert recipients
    # and logs failures itself
    message, sent = get_core_settings().send_mail(
        subject, body, override_recipients=emails or []
    )
    if not sent:
        logger.error(f"script results mail for {agent.hostname} not sent: {message}")


@app.task
def clear_faults_task(older_than_days: int) -> None:
    from core.tasks import _get_agent_qs

    cutoff = djangotime.now() - dt.timedelta(days=older_than_days)
    for agent in _get_agent_qs().filter(last_seen__lt=cutoff):
        for check in agent.get_checks_with_policies():
            result = getattr(check, "check_result", None)
            if not result:
                continue
            result.status = CheckStatus.PASSING
            result.save(update_fields=["status"])
            for alert in Alert.objects.filter(
                agent=agent, assigned_check=check, resolved=False
            ):
                alert.resolve()

        for flag in _OVERDUE_FLAGS:
            setattr(agent, flag, False)
        agent.save(update_fields=list(_OVERDUE_FLAGS))


@app.task
def prune_agent_history(older_than_days: int) -> str:
    cutoff = djangotime.now() - dt.timedelta(days=older_than_days)
    AgentHistory.objects.filter(time__lt=cutoff).delete()
    return "ok"


@app.task
def bulk_recover_agents_task() -> None:
    call_command("bulk_restart_agents")
