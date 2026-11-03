# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import asyncio
import codecs
import fcntl
import os
import signal
import struct
import subprocess
import termios
import threading
import uuid
from contextlib import suppress

from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncJsonWebsocketConsumer, JsonWebsocketConsumer
from django.db.models import Count, Q

from ulrmm.constants import AuditActionType, AuditObjType, AgentMonType
from ulrmm.logger import logger


def _role_has_perm(user, perm: str) -> bool:
    if user.is_superuser or (getattr(user, "role", None) and user.role.is_superuser):
        return True
    role = getattr(user, "role", None)
    if not role:
        return False
    return bool(getattr(role, perm))


@database_sync_to_async
def _dashinfo_payload(user) -> dict:
    from agents.models import Agent
    from core.stats import _offline_q
    from ulrmm.helpers import days_until_cert_expires

    agents = Agent.objects.filter_by_role(user)
    counts = agents.aggregate(
        total_server_count=Count("pk", filter=Q(monitoring_type=AgentMonType.SERVER)),
        total_workstation_count=Count(
            "pk", filter=Q(monitoring_type=AgentMonType.WORKSTATION)
        ),
        total_server_offline_count=Count(
            "pk", filter=Q(monitoring_type=AgentMonType.SERVER) & _offline_q()
        ),
        total_workstation_offline_count=Count(
            "pk", filter=Q(monitoring_type=AgentMonType.WORKSTATION) & _offline_q()
        ),
    )
    try:
        cert_days = days_until_cert_expires()
    except Exception:
        cert_days = None
    return {
        "total_server_offline_count": counts["total_server_offline_count"],
        "total_workstation_offline_count": counts["total_workstation_offline_count"],
        "total_server_count": counts["total_server_count"],
        "total_workstation_count": counts["total_workstation_count"],
        "days_until_cert_expires": cert_days,
    }


class DashInfo(AsyncJsonWebsocketConsumer):
    async def connect(self):
        self.user = self.scope.get("user")
        if (
            self.user is None
            or getattr(self.user, "is_anonymous", True)
            or getattr(self.user, "block_dashboard_login", False)
        ):
            await self.close()
            return
        await self.accept()
        self.task = asyncio.create_task(self._loop())

    async def disconnect(self, code):
        task = getattr(self, "task", None)
        if task:
            task.cancel()

    async def receive_json(self, content, **kwargs):
        pass

    async def _loop(self):
        while True:
            try:
                await self.send_json(
                    {
                        "action": "dashboard.agentcount",
                        "data": await _dashinfo_payload(self.user),
                    }
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.debug("dashinfo compute failed", exc_info=True)
            await asyncio.sleep(30)


class TerminalConsumer(JsonWebsocketConsumer):
    def connect(self):
        from accounts.utils import console_stepup_remaining

        from core.models import CoreSettings

        user = self.scope.get("user")
        if user is None:
            self.close(4401)
            return
        if getattr(user, "is_anonymous", True):
            self.close()
            return
        if not getattr(user, "is_authenticated", False):
            self.close(4401)
            return

        core = CoreSettings.objects.first()
        if not core or not core.web_terminal_enabled:
            self.close(4401)
            return

        if getattr(user, "block_dashboard_login", False) or not _role_has_perm(
            user, "can_use_webterm"
        ):
            self.close(4401)
            return

        if console_stepup_remaining(user) <= 0:
            self.close(4403)
            return

        if getattr(self, "child_pid", None):
            return

        self.accept()

        from logs.models import AuditLog

        client = self.scope.get("client") or ["", 0]
        AuditLog.objects.create(
            username=user.username,
            object_type=AuditObjType.CORE,
            action=AuditActionType.REMOTE_SESSION,
            message=f"{user.username} opened the server web terminal.",
            debug_info={"ip": client[0]},
        )

        self.connected = True
        self.decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        # the PTY exists before any thread so the reader never races self.fd
        self.master_fd, self.slave_fd = os.openpty()
        self.shell_thread = threading.Thread(target=self._spawn, daemon=True)
        self.reader_thread = threading.Thread(target=self._read_loop, daemon=True)
        self.shell_thread.start()
        self.reader_thread.start()

    def _spawn(self):
        env = {**os.environ, "TERM": "xterm"}
        try:
            self.proc = subprocess.Popen(
                ["/bin/bash"],
                stdin=self.slave_fd,
                stdout=self.slave_fd,
                stderr=self.slave_fd,
                cwd=os.path.expanduser("~"),
                env=env,
                start_new_session=True,
            )
            self.child_pid = self.proc.pid
            # the parent keeps only the master end
            os.close(self.slave_fd)
            self.proc.wait()
        except Exception:
            logger.debug("web terminal shell failed", exc_info=True)
        finally:
            if getattr(self, "connected", False):
                self.close(4030)

    def _read_loop(self):
        while True:
            try:
                data = os.read(self.master_fd, 1024)
            except OSError:
                break
            if not data:
                break
            text = self.decoder.decode(data)
            if text:
                self.send_json(
                    {
                        "action": "rmmcli.output",
                        "data": {"output": text, "messageId": str(uuid.uuid4())},
                    }
                )

    def receive_json(self, content, **kwargs):
        action = content.get("action")
        data = content.get("data") or {}
        if action == "rmmcli.input":
            self._write(data.get("input", ""))
        elif action == "rmmcli.resize":
            self._resize(data.get("rows", 0), data.get("cols", 0))
        elif action == "rmmcli.disconnect":
            self._kill()
            self.send_json(
                {"action": "rmmcli.output", "data": {"output": "Terminal killed!"}}
            )

    def _write(self, text):
        with suppress(Exception):
            os.write(self.master_fd, text.encode())

    def _resize(self, rows, cols):
        with suppress(Exception):
            winsize = struct.pack("HHHH", int(rows), int(cols), 0, 0)
            fcntl.ioctl(self.master_fd, termios.TIOCSWINSZ, winsize)

    def _kill(self):
        pid = getattr(self, "child_pid", None)
        if pid:
            with suppress(Exception):
                os.killpg(os.getpgid(pid), signal.SIGKILL)

    def disconnect(self, code):
        self.connected = False
        self._kill()
        with suppress(Exception):
            os.close(self.master_fd)
