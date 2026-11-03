#!/usr/bin/env python
# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Entry point for Django management commands of the server."""

import os
import sys


def main() -> None:
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ulrmm.settings")
    try:
        from django.core import management
    except ImportError as exc:
        raise ImportError(
            "Django is not importable; activate the api/env virtualenv "
            "(or install requirements.txt) and try again."
        ) from exc
    management.execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()
