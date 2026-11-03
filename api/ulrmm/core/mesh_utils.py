# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import asyncio
import json
import random
import re
import secrets
import string
import traceback
from functools import cached_property

import websockets

from ulrmm.constants import ULRMM_WS_MAX_SIZE
from ulrmm.logger import logger

# old rights mask minus agent console (0x10), run commands (0x20000) and guest
# sharing (0x80000), plus "no terminal" (0x200) and "no files" (0x400)
MESH_RIGHTS_BASE = (4088024 & ~(0x10 | 0x20000 | 0x80000)) | 0x200 | 0x400
# base rights with the terminal and file browser enabled, granted per device
# after a TOTP step-up
MESH_RIGHTS_CONSOLE = MESH_RIGHTS_BASE & ~(0x200 | 0x400)

_RMM_USER_RE = re.compile(r".*___\d+")


def build_mesh_display_name(first_name, last_name, company_name) -> str:
    name = first_name or ""
    if last_name:
        name = f"{name} {last_name}"
    name = name.strip()
    if name and company_name:
        return f"{name} - {company_name}"
    if not name and company_name:
        return company_name
    return name


def mesh_node_name(name: str) -> str:
    return (name or "").strip()[:64]


def has_mesh_perms(*, user) -> bool:
    from accounts.utils import has_superuser_rights

    if has_superuser_rights(user):
        return True
    role = getattr(user, "role", None)
    return bool(role and role.can_use_mesh)


def make_mesh_password() -> str:
    rng = random.SystemRandom()
    chars = [secrets.choice(string.ascii_letters + string.digits) for _ in range(29)]
    chars.append(secrets.choice("!@#$"))
    rng.shuffle(chars)
    return "".join(chars)


def transform_rmm(nodes) -> list:
    result = []
    try:
        for node in nodes:
            try:
                result.append(
                    {
                        "node_id": node["node_id"],
                        "user_ids": [link["_id"] for link in node.get("links", [])],
                    }
                )
            except (KeyError, TypeError):
                continue
    except Exception:
        logger.error(traceback.format_exc())
    return result


def transform_mesh(nodes_by_mesh) -> list:
    result = []
    try:
        for _mesh_id, nodes in (nodes_by_mesh or {}).items():
            for node in nodes:
                links = node.get("links")
                if not links:
                    continue
                user_ids, rights = [], {}
                for user_id, link in links.items():
                    if _RMM_USER_RE.match(user_id):
                        user_ids.append(user_id)
                        rights[user_id] = link.get("rights")
                result.append(
                    {
                        "node_id": node["_id"],
                        "user_ids": user_ids,
                        "rights": rights,
                    }
                )
    except Exception:
        logger.error(traceback.format_exc())
    return result


class MeshSync:
    def __init__(self, uri: str) -> None:
        self.uri = uri

    async def _action(self, *, payload, wait, timeout):
        async with websockets.connect(self.uri, max_size=ULRMM_WS_MAX_SIZE) as ws:
            await ws.send(json.dumps(payload))
            if not wait:
                return None
            while True:
                try:
                    raw = await asyncio.wait_for(ws.recv(), timeout=timeout)
                except asyncio.TimeoutError:
                    logger.error("Timeout reached.")
                    return None
                data = json.loads(raw)
                if data.get("action") == payload["action"]:
                    return data

    def mesh_action(self, *, payload, wait=True, timeout=120):
        payload = {**payload, "responseid": "meshctrl"}
        return asyncio.run(self._action(payload=payload, wait=wait, timeout=timeout))

    @cached_property
    def mesh_users(self) -> dict:
        reply = self.mesh_action(payload={"action": "users"})
        if not reply:
            logger.warning("mesh users: no reply from MeshCentral")
            return {}
        users = {}
        for user in reply.get("users") or []:
            user_id = user.get("_id", "")
            if _RMM_USER_RE.match(user_id):
                users[user_id] = user
        return users

    def get_unique_mesh_users(self, agents) -> set:
        ids = set()
        for node in agents:
            for link in node.get("links", []) or []:
                if link.get("_id"):
                    ids.add(link["_id"])
        return ids

    def add_users_to_node(
        self, *, node_id, user_ids, rights=MESH_RIGHTS_BASE, wait=False
    ):
        return self.mesh_action(
            payload={
                "action": "adddeviceuser",
                "nodeid": node_id,
                "usernames": [uid.replace("user//", "") for uid in user_ids],
                "rights": rights,
                "remove": False,
            },
            wait=wait,
            timeout=20,
        )

    def delete_users_from_node(self, *, node_id, user_ids):
        self.mesh_action(
            payload={
                "action": "adddeviceuser",
                "nodeid": node_id,
                "userids": list(user_ids),
                "rights": 0,
                "remove": True,
            },
            wait=False,
        )

    def rename_node(self, *, node_id, name, wait=False):
        return self.mesh_action(
            payload={"action": "changedevice", "nodeid": node_id, "name": name},
            wait=wait,
            timeout=20,
        )

    def update_mesh_displayname(self, *, user_info):
        self.mesh_action(
            payload={
                "action": "edituser",
                "id": user_info["_id"],
                "realname": user_info["full_name"],
            },
            wait=False,
        )

    def add_user_to_mesh(self, *, user_info):
        payload = {"action": "adduser"}
        payload.update(username=user_info["username"], email=user_info["email"])
        payload["pass"] = make_mesh_password()
        payload.update(
            dict.fromkeys(("resetNextLogin", "randomPassword", "removeEvents"), False)
        )
        payload["emailVerified"] = True
        self.mesh_action(payload=payload, wait=False)
        if user_info.get("full_name"):
            self.update_mesh_displayname(user_info=user_info)

    def delete_user_from_mesh(self, *, mesh_user_id):
        self.mesh_action(
            payload={"action": "deleteuser", "userid": mesh_user_id},
            wait=False,
        )
