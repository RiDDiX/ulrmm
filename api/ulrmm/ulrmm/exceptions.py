# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2


class NatsDown(Exception):
    def __str__(self) -> str:
        return "Unable to connect to NATS"
