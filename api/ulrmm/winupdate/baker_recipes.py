# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from itertools import cycle

from model_bakery.recipe import Recipe, seq

from .models import WinUpdate

# rotates through every severity the agent reports, including none
winupdate = Recipe(
    WinUpdate,
    kb=seq("KB50000"),
    guid=seq("5b0d6a3e-0000-4000-8000-"),
    severity=cycle(["Critical", "Important", "Moderate", "Low", ""]),
)

approved_winupdate = winupdate.extend(action="approve")
