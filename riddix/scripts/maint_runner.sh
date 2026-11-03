#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

# Runs one maintenance request from the dashboard. ulrmm-maint.path starts
# ulrmm-maint.service when the web app drops MAINT_DIR/request; the request
# names one action, nothing else is read from it. Output goes to
# MAINT_DIR/<action>.log, the result to MAINT_DIR/<action>.state.json.
#
# Everything sits in main(): update.sh resets the checkout this file lives in,
# and bash would otherwise read the new file from the old offset.

MAINT_DIR=${MAINT_DIR:-/var/lib/ulrmm-maint}

write_state() { # action state exit_code started finished
  local tmp="${MAINT_DIR}/.${1}.state.json"
  printf '{"action": "%s", "state": "%s", "exit_code": %s, "started": %s, "finished": %s}\n' \
    "$1" "$2" "${3:-null}" "${4:-null}" "${5:-null}" >"$tmp" &&
    mv -f "$tmp" "${MAINT_DIR}/${1}.state.json"
}

main() {
  umask 077
  exec 9>"${MAINT_DIR}/lock" || exit 1
  # one action at a time. A second runner waits here; leaving the request
  # behind would make the path unit start the service again at once.
  flock 9 || exit 1

  [ -f "${MAINT_DIR}/request" ] || exit 0
  local action
  action=$(head -c 32 "${MAINT_DIR}/request" | tr -cd 'a-z')
  rm -f "${MAINT_DIR}/request"

  local -a cmd
  case "$action" in
  update) cmd=(/usr/bin/env bash /rmm/update.sh --yes) ;;
  backup) cmd=(/rmm/backup.sh) ;;
  schedule) cmd=(/rmm/backup.sh --schedule) ;;
  *) exit 0 ;;
  esac

  local log="${MAINT_DIR}/${action}.log" started rc state
  : >"$log"
  started=$(date +%s)
  write_state "$action" running "" "$started"

  cd "${HOME:-/tmp}" || cd /tmp || exit 1
  # the action gets the umask of a shell run: under 077 its sudo npm install -g
  # left the global npm readable for root only, and the next update had no npm
  (umask 022 && "${cmd[@]}") >>"$log" 2>&1 </dev/null
  rc=$?

  state=done
  [ "$rc" -eq 0 ] || state=failed
  write_state "$action" "$state" "$rc" "$started" "$(date +%s)"
}

main "$@"
exit
