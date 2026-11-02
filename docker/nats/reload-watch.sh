#!/bin/sh
# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

# Django rewrites nats-rmm.conf and cannot signal nats-server in another
# container, so this watches the file and sends HUP on change.
set -eu
conf=/conf/nats-rmm.conf

until [ -f "$conf" ]; do
  sleep 3
done

nats-server -c "$conf" &
pid=$!
trap 'kill -TERM "$pid" 2>/dev/null' TERM INT

sum=$(sha256sum "$conf")
while kill -0 "$pid" 2>/dev/null; do
  sleep 3
  new=$(sha256sum "$conf" 2>/dev/null || true)
  if [ -n "$new" ] && [ "$new" != "$sum" ]; then
    sum=$new
    kill -HUP "$pid"
  fi
done
wait "$pid"
