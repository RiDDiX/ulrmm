# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import asyncio
import re
import uuid
from contextlib import suppress
from types import SimpleNamespace
from typing import Any, Optional

import msgpack
import nats
import validators
from asgiref.sync import sync_to_async
from channels.generic.websocket import AsyncJsonWebsocketConsumer
from django.contrib.auth.models import AnonymousUser
from django.core.cache import cache
from django.http import Http404

from accounts.utils import console_stepup_remaining
from agents.models import Agent, AgentHistory, AgentPlat
from agents.utils import is_posix_abs_path, is_windows_path
from deploy import envelope
from logs.models import AuditLog
from ulrmm.constants import DARWIN_TOKENS, FREEBSD_TOKENS, LINUX_TOKENS, WINDOWS_TOKENS
from ulrmm.constants import AgentHistoryType, AuditActionType, AuditObjType
from ulrmm.helpers import agent_ver, setup_nats_options
from ulrmm.logger import logger
from ulrmm.permissions import _has_perm, _has_perm_on_agent

# channel name -> {cmd_id: (stop event, stream task)} of the running commands
active_streams: dict[str, dict[str, tuple[asyncio.Event, asyncio.Future]]] = {}

STREAM_MIN_VERSION = "2.10.0"
MAX_STREAM_TIMEOUT = 3600
MAX_STREAMS_PER_SOCKET = 5
# cmd_id ends up in a NATS subject and a channel-layer group name
_CMD_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")


def _client_ip(scope) -> str:
    client = scope.get("client") or ("",)
    return client[0] or ""


def _allowed(user, flag: str, agent_id: str) -> bool:
    """Role flag plus agent scope. Unknown agents are refused."""
    try:
        return bool(
            _has_perm(SimpleNamespace(user=user), flag)
            and _has_perm_on_agent(user, agent_id)
        )
    except Http404:
        return False


# Database work runs through asgiref's sync_to_async. Channels' wrapper would
# also close old connections; the websocket auth middleware already does that
# on every connect.


async def _check(check, *args) -> bool:
    # has_perm is a plain method, run off the event loop; a coroutine
    # function in its place is awaited directly
    if asyncio.iscoroutinefunction(check):
        return bool(await check(*args))
    return bool(await sync_to_async(check)(*args))


@sync_to_async
def _load_agent(agent_id: str) -> Optional[Agent]:
    return Agent.objects.filter(agent_id=agent_id).first()


async def _accept_and_refuse(consumer, error: str, status: int, **close_kw) -> None:
    # the client only reads the reason from an accepted socket
    await consumer.accept()
    await consumer.send_json({"error": error, "status": status})
    await consumer.close(**close_kw)


def _rejected_user(user) -> Optional[tuple]:
    """close() arguments for a socket user that may not connect, else None."""
    if user is None or isinstance(user, AnonymousUser):
        return ()
    if not user.is_authenticated:
        return (4401,)
    if getattr(user, "block_dashboard_login", False):
        return ()
    return None


class CommandStreamConsumer(AsyncJsonWebsocketConsumer):
    authorized = False
    cmd_id: Optional[str] = None
    group_name = ""
    user = None
    agent_id = ""

    def has_perm(self, user, agent_id: str) -> bool:
        return _allowed(user, "can_send_cmd", agent_id)

    async def connect(self):
        self.user = self.scope.get("user")
        rejected = _rejected_user(self.user)
        if rejected is not None:
            await self.close(*rejected)
            return

        self.agent_id = self.scope["url_route"]["kwargs"]["agent_id"]
        if not await _check(self.has_perm, self.user, self.agent_id):
            await _accept_and_refuse(
                self,
                "You do not have permission to perform this action.",
                403,
                code=4003,
            )
            return

        agent = await _load_agent(self.agent_id)
        if agent is None:
            await self.close(code=4404)
            return
        if agent_ver(agent.version) < agent_ver(STREAM_MIN_VERSION):
            await _accept_and_refuse(
                self,
                "The streaming feature requires agent version "
                f"{STREAM_MIN_VERSION} or higher.",
                400,
            )
            return

        # groups are joined per command, not here
        await self.accept()
        self.authorized = True

    async def receive_json(self, content, **kwargs):
        if not self.authorized:
            await self.close(code=4403)
            return

        try:
            cmd = content["cmd"]
            if not isinstance(cmd, str) or not cmd.strip():
                raise ValueError("cmd")
            shell = content.get("shell") or "cmd"
            if shell == "custom" and content.get("custom_shell"):
                shell = content["custom_shell"]
            if not isinstance(shell, str):
                raise ValueError("shell")
            run_as_user = bool(content.get("run_as_user", False))
            timeout = int(content.get("timeout", 30))
        except (KeyError, TypeError, ValueError, AttributeError):
            await self.send_json({"error": "Invalid command payload"})
            return
        timeout = min(max(timeout, 1), MAX_STREAM_TIMEOUT)

        streams = active_streams.setdefault(self.channel_name, {})
        if sum(1 for _, task in streams.values() if not task.done()) >= (
            MAX_STREAMS_PER_SOCKET
        ):
            await self.send_json({"error": "Too many commands are still running."})
            return

        requested = content.get("cmd_id")
        if isinstance(requested, str) and _CMD_ID.fullmatch(requested):
            cmd_id = requested
        else:
            cmd_id = uuid.uuid4().hex
        # one cmd_id, one socket: nobody else can join the output group
        if not await self._claim(cmd_id, timeout):
            await self.send_json({"error": "This command id is already in use."})
            return

        agent = await _load_agent(self.agent_id)
        if agent is None:
            await self.close(code=4404)
            return

        self.cmd_id = cmd_id
        self.group_name = f"agent_cmd_{self.agent_id}_{cmd_id}"
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        self._joined().add(self.group_name)
        await self.send_json({"cmd_id": cmd_id})

        history_pk = await self._record(agent, cmd, shell)
        data = {
            "func": "rawcmd",
            "id": history_pk,
            "timeout": timeout,
            "stream": True,
            "run_as_user": run_as_user,
            "payload": {"command": cmd, "shell": shell, "cmd_id": cmd_id},
        }
        stop = asyncio.Event()
        task = asyncio.ensure_future(
            agent.nats_stream_cmd(
                data,
                timeout=timeout + 2,
                stop_evt=stop,
                output_subject=f"{self.agent_id}.cmdoutput.{cmd_id}",
                group=self.group_name,
            )
        )
        streams[cmd_id] = (stop, task)
        task.add_done_callback(lambda _: self._forget(cmd_id, task))

    async def _claim(self, cmd_id: str, timeout: int) -> bool:
        key = f"agent_cmd_owner_{self.agent_id}_{cmd_id}"
        if await cache.aadd(key, self.channel_name, timeout + 60) or (
            await cache.aget(key) == self.channel_name
        ):
            self._claimed().add(cmd_id)
            return True
        return False

    def _joined(self) -> set:
        if not hasattr(self, "_groups"):
            self._groups = set()
        return self._groups

    def _claimed(self) -> set:
        if not hasattr(self, "_claims"):
            self._claims = set()
        return self._claims

    async def _release_claims(self) -> None:
        for cmd_id in self._claimed():
            key = f"agent_cmd_owner_{self.agent_id}_{cmd_id}"
            if await cache.aget(key) == self.channel_name:
                await cache.adelete(key)

    def _forget(self, cmd_id: str, task) -> None:
        streams = active_streams.get(self.channel_name)
        if streams and streams.get(cmd_id, (None, None))[1] is task:
            del streams[cmd_id]
            if not streams:
                active_streams.pop(self.channel_name, None)

    @sync_to_async
    def _record(self, agent: Agent, cmd: str, shell: str) -> int:
        username = self.user.username
        history = AgentHistory.objects.create(
            agent=agent,
            type=AgentHistoryType.CMD_RUN,
            command=cmd,
            username=username[:50],
        )
        AuditLog.audit_raw_command(
            username, agent, cmd, shell, debug_info={"ip": _client_ip(self.scope)}
        )
        return history.pk

    async def stream_output(self, event):
        await self.send_json(
            {
                key: event[key]
                for key in ("output", "done", "exit_code", "cmd_id")
                if key in event
            }
        )

    async def disconnect(self, code):
        streams = active_streams.pop(self.channel_name, {})
        for stop, _ in streams.values():
            stop.set()
        # a cancelled disconnect still raises; a failed or cancelled stream does not
        await asyncio.gather(
            *(task for _, task in streams.values()), return_exceptions=True
        )

        groups = set(self._joined())
        if self.group_name:
            groups.add(self.group_name)
        for group in groups:
            await self.channel_layer.group_discard(group, self.channel_name)
        await self._release_claims()


class InvalidTerminalShellError(Exception):
    pass


_SHELL_RULES = {
    AgentPlat.WINDOWS: (
        WINDOWS_TOKENS,
        is_windows_path,
        "cmd",
        "Invalid shell. Use 'cmd', 'powershell', or an absolute Windows .exe path.",
    ),
    AgentPlat.LINUX: (
        LINUX_TOKENS,
        is_posix_abs_path,
        "bash",
        "Invalid shell. Use a supported shell (e.g. bash) or an absolute POSIX path.",
    ),
    AgentPlat.DARWIN: (
        DARWIN_TOKENS,
        is_posix_abs_path,
        "bash",
        "Invalid shell. Use a supported shell (e.g. zsh, bash) or an absolute "
        "POSIX path.",
    ),
    AgentPlat.FREEBSD: (
        FREEBSD_TOKENS,
        is_posix_abs_path,
        "sh",
        "Invalid shell. Use 'sh', 'bash' or an absolute POSIX path.",
    ),
}


class TerminalStreamConsumer(AsyncJsonWebsocketConsumer):
    """Interactive terminal on an agent, open while the console step-up lasts."""

    user = None
    agent_id = ""
    session_id = ""
    group_name = ""
    nc = None
    sub = None
    started = False
    killed = False
    message_id = 0
    _expiry: Optional[asyncio.Task] = None
    _start_lock: Optional[asyncio.Lock] = None
    _publish_lock: Optional[asyncio.Lock] = None
    # sec2: frames are opened with the session of the last sealed send
    _sealed = False
    _e2e: Optional[dict] = None
    _frame_refused = False

    def has_perm(self, user, agent_id: str) -> bool:
        return _allowed(user, "can_use_terminal", agent_id)

    async def connect(self):
        self.user = self.scope.get("user")
        rejected = _rejected_user(self.user)
        if rejected is not None:
            await self.close(*rejected)
            return

        kwargs = self.scope["url_route"]["kwargs"]
        if not validators.uuid(kwargs.get("session_id", "")):
            await self.close()
            return
        self.agent_id, self.session_id = kwargs["agent_id"], kwargs["session_id"]

        if not await _check(self.has_perm, self.user, self.agent_id):
            await self.close(code=4003)
            return
        if await _load_agent(self.agent_id) is None:
            await self.close(code=4404)
            return

        remaining = await sync_to_async(console_stepup_remaining)(self.user)
        if remaining <= 0:
            await self.close(code=4403)
            return

        # the output group is per session; a session belongs to one user
        owner = f"terminal_owner_{self.agent_id}_{self.session_id}"
        if not await cache.aadd(owner, self.user.pk, remaining + 60):
            if await cache.aget(owner) != self.user.pk:
                await self.close(code=4003)
                return

        self.group_name = f"terminal_{self.agent_id}_{self.session_id}"
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()
        self._expiry = asyncio.ensure_future(self._close_after(remaining))

    async def _close_after(self, seconds: float) -> None:
        await asyncio.sleep(seconds)
        await self.close(code=4403)

    async def receive_json(self, content, **kwargs):
        kind = content.get("action")
        if kind == "start":
            await self._start_terminal(content)
        elif kind == "input":
            await self._send_input(content.get("data"))
        elif kind == "resize":
            await self._send_resize(content.get("rows"), content.get("cols"))
        elif kind == "kill":
            self.killed = True
            await self._send_kill()
        else:
            await self.send_json({"error": f"Unknown action: {kind}"})

    # --- shell choice -------------------------------------------------------

    def _resolve_explicit_shell(self, shell: str, plat: str) -> str:
        """The shell a user asked for, or InvalidTerminalShellError."""
        rule = _SHELL_RULES.get(plat)
        if rule is None:
            raise InvalidTerminalShellError("Unsupported agent platform.")
        tokens, path_ok, _, message = rule
        shell = (shell or "").strip()
        if shell.lower() in tokens:
            return shell.lower()
        if path_ok(shell):
            return shell
        raise InvalidTerminalShellError(message)

    def _resolve_default_shell(self, shell: str, plat: str) -> str:
        """The agent's default shell; invalid values use the platform default."""
        rule = _SHELL_RULES.get(plat)
        fallback = rule[2] if rule else "cmd"
        try:
            return self._resolve_explicit_shell(shell, plat)
        except InvalidTerminalShellError:
            return fallback

    # --- session --------------------------------------------------------------

    @sync_to_async
    def _terminal_target(self) -> Optional[tuple[str, str, str]]:
        agent = Agent.objects.filter(agent_id=self.agent_id).first()
        if agent is None:
            return None
        return agent.plat, agent.hostname, agent.effective_default_shell

    @sync_to_async
    def _audit_start(self, hostname: str, shell: str) -> None:
        username = self.user.username
        AuditLog.objects.create(
            username=username,
            agent=hostname,
            agent_id=self.agent_id,
            object_type=AuditObjType.AGENT,
            action=AuditActionType.EXEC_COMMAND,
            message=f"{username} opened a terminal session ({shell}) on {hostname}",
            debug_info={"ip": _client_ip(self.scope)},
        )

    async def _start_terminal(self, content: dict) -> None:
        if self._start_lock is None:
            self._start_lock = asyncio.Lock()
        async with self._start_lock:
            if self.started:
                return
            self.started = True
            try:
                target = await self._terminal_target()
                if target is None:
                    raise LookupError(self.agent_id)
                plat, hostname, default_shell = target

                requested = content.get("shell")
                requested = requested.strip() if isinstance(requested, str) else ""
                if requested:
                    shell = self._resolve_explicit_shell(requested, plat)
                else:
                    shell = self._resolve_default_shell(default_shell, plat)
                run_as_user = plat == AgentPlat.WINDOWS and bool(
                    content.get("run_as_user", False)
                )

                await self._ensure_nats()
                if self.sub is not None:
                    with suppress(Exception):
                        await self.sub.unsubscribe()
                self._sealed = await envelope.amode(self.agent_id) != envelope.LEGACY
                # listen first, the agent may answer at once
                self.sub = await self.nc.subscribe(
                    f"{self.agent_id}.terminal.{self.session_id}", cb=self._on_output
                )
                await self._nats_publish(
                    {
                        "func": "terminal_start",
                        "payload": {"session_id": self.session_id, "shell": shell},
                        "run_as_user": run_as_user,
                    }
                )
                await self._audit_start(hostname, shell)
            except InvalidTerminalShellError as e:
                self.started = False
                await self._send_terminal_error(str(e), code="invalid_shell")
            except Exception:
                logger.exception("terminal start failed on %s", self.agent_id)
                self.started = False
                await self._send_terminal_error(
                    "Failed to start terminal session.", code="terminal_start_failed"
                )

    async def _on_output(self, msg) -> None:
        try:
            raw = msg.data
            if self._sealed:
                try:
                    raw = envelope.open_frame(
                        self.agent_id, msg.subject, raw, self._e2e
                    )
                except envelope.Refused as e:
                    if not self._frame_refused:
                        self._frame_refused = True
                        await sync_to_async(envelope.event)(self.agent_id, str(e))
                    return
            try:
                # agents up to 2.09.10.2026 may cut a chunk inside a character
                frame = msgpack.loads(raw, unicode_errors="replace")
            except Exception:
                frame = raw

            event: dict[str, Any] = {
                "type": "stream_output",
                "session_id": self.session_id,
            }
            if isinstance(frame, dict):
                output = frame.get("output")
                if isinstance(output, bytes):
                    output = output.decode("utf-8", errors="ignore")
                elif not isinstance(output, str):
                    output = None
                done = frame.get("done") is True
                if done:
                    self.started = False
                    if (
                        frame.get("exit_code") == 1
                        and output
                        and output.startswith("[ERROR] ")
                    ):
                        await self._send_terminal_error(
                            output[len("[ERROR] ") :], code="terminal_start_failed"
                        )
                        return
                if output and output.startswith("[INFO] "):
                    await self.send_json(
                        {
                            "action": "terminal_info",
                            "message": output[len("[INFO] ") :],
                            "code": "terminal_fallback",
                        }
                    )
                    return
                if output is not None:
                    event["output"] = output
                if done:
                    event["done"] = True
                if "exit_code" in frame:
                    event["exit_code"] = frame["exit_code"]
            elif isinstance(frame, bytes):
                event["output"] = frame.decode("utf-8", errors="ignore")
            elif isinstance(frame, str):
                event["output"] = frame
            else:
                event["output"] = str(frame)

            self.message_id += 1
            event["messageId"] = str(self.message_id)
            await self.channel_layer.group_send(self.group_name, event)
        except Exception as exc:
            await self.channel_layer.group_send(
                self.group_name,
                {
                    "type": "stream_output",
                    "session_id": self.session_id,
                    "output": f"[ERROR] Failed to process agent output: {exc}",
                },
            )

    async def stream_output(self, event):
        await self.send_json(
            {
                "action": "rmmcli.output",
                "data": {
                    "output": event.get("output", ""),
                    "session_id": event.get("session_id", ""),
                    "exit_code": event.get("exit_code"),
                    "done": event.get("done", False),
                    "messageId": event.get("messageId", ""),
                },
            }
        )

    async def _send_terminal_error(self, error: str, code: str) -> None:
        await self.send_json({"action": "terminal_error", "error": error, "code": code})

    # --- NATS ----------------------------------------------------------------

    async def _ensure_nats(self) -> None:
        if self.nc is None or self.nc.is_closed:
            self.nc = await nats.connect(**setup_nats_options())

    async def _nats_publish(self, data: dict) -> None:
        if self._publish_lock is None:
            self._publish_lock = asyncio.Lock()
        async with self._publish_lock:
            await self._ensure_nats()
            try:
                ctx = await envelope.publish(
                    self.nc, self.agent_id, msgpack.dumps(data)
                )
                self._e2e = ctx or self._e2e
            except envelope.Refused:
                raise
            except Exception:
                # a broken connection is dropped; the next publish reconnects
                nc, self.nc = self.nc, None
                with suppress(Exception):
                    await nc.close()
                raise

    async def _send_input(self, data) -> None:
        if not self.started or not data or not isinstance(data, str):
            return
        await self._nats_publish(
            {
                "func": "terminal_input",
                "payload": {"session_id": self.session_id, "data": data},
            }
        )

    async def _send_resize(self, rows, cols) -> None:
        if not self.started or rows is None or cols is None:
            return
        try:
            rows, cols = int(rows), int(cols)
        except (TypeError, ValueError):
            return
        if rows < 1 or cols < 1:
            return
        payload = {"session_id": self.session_id, "rows": str(rows), "cols": str(cols)}
        await self._nats_publish({"func": "terminal_resize", "payload": payload})

    async def _send_kill(self) -> None:
        await self._nats_publish(
            {"func": "terminal_kill", "payload": {"session_id": self.session_id}}
        )

    async def disconnect(self, code):
        if self._expiry is not None:
            self._expiry.cancel()
            self._expiry = None

        if self.group_name:
            await self.channel_layer.group_discard(self.group_name, self.channel_name)

        # without a NATS connection no session was ever started
        if not self.killed and self.nc is not None:
            with suppress(Exception):
                await self._send_kill()

        sub, self.sub = self.sub, None
        if sub is not None:
            with suppress(Exception):
                await sub.unsubscribe()
        if self.nc is not None:
            with suppress(Exception):
                await self.nc.close()
        self.nc = None
