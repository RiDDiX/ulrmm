# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import asyncio
from typing import Any

import msgpack
import nats
from nats.errors import NoRespondersError
from nats.errors import TimeoutError as NatsTimeoutError

from deploy import envelope
from ulrmm.exceptions import NatsDown
from ulrmm.helpers import setup_nats_options
from ulrmm.logger import logger

NATS_DATA = dict[str, Any]
BULK_NATS_TASKS = list[tuple[str, Any]]


async def _anats_message(*, nc, subject, data) -> None:
    try:
        payload = msgpack.dumps(data)
    except Exception:
        # never log the payload itself, it may carry agent data
        logger.error("dropping NATS message to %s: payload not serializable", subject)
        return
    try:
        await envelope.publish(nc, subject, payload)
    except envelope.Refused as e:
        logger.warning("dropping NATS message to %s: %s", subject, e)


async def abulk_nats_command(*, items: BULK_NATS_TASKS) -> None:
    try:
        nc = await nats.connect(**setup_nats_options())
    except Exception:
        raise NatsDown

    try:
        await asyncio.gather(
            *(
                _anats_message(nc=nc, subject=subject, data=data)
                for subject, data in items
            )
        )
        await nc.flush()
    finally:
        await nc.close()


async def a_nats_cmd(*, nc, sub: str, data, timeout: int = 10):
    payload = msgpack.dumps(data)
    try:
        raw = await envelope.request(nc, sub, payload, timeout)
    except (NatsTimeoutError, NoRespondersError):
        return "timeout"
    except envelope.Refused as e:
        return e.answer

    try:
        return msgpack.loads(raw)
    except Exception as e:
        return str(e)
