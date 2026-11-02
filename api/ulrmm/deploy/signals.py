# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

from django.dispatch import Signal

# sent once the enrolling transaction has committed: agent=, deployment=
agent_enrolled = Signal()
