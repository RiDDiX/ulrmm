# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.core.management.base import BaseCommand

from reporting.schema import write_query_schema
from reporting.utils import copy_plotly_js


class Command(BaseCommand):
    help = "Write the data query schema and the plotly.js copy for report charts"

    def handle(self, *args, **kwargs):
        self.stdout.write(f"Wrote {write_query_schema()}")
        self.stdout.write(f"Wrote {copy_plotly_js()}")
