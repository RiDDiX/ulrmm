#!/bin/sh
# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

# baseline check: a file exists. DET_* env only.
# server reads the last line: ULRMM-DET {"found":bool,"version":""}.

found=false
[ "${DET_TYPE:-}" = file ] && [ -n "${DET_PATH:-}" ] && [ -e "$DET_PATH" ] && found=true
printf 'ULRMM-DET {"found":%s,"version":""}\n' "$found"
