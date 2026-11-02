#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

# Builds the assets of one release: the server tree at HEAD, the built
# dashboard, the manifest and its Ed25519 signature.
#
#   riddix/scripts/release_build.sh <VERSION> [--web-dir DIR] [--prebuilt] [--out DIR] [--key-file FILE]
#
# The signing seed (base64, 32 bytes) comes from --key-file or ULRMM_RELEASE_KEY.
# --prebuilt packs DIR/dist as built elsewhere and runs no npm (CI builds it in
# a job without the key). Needs git, npm, GNU tar and python3 with cryptography.
set -euo pipefail

PUBKEY='9HiAMY1u6eJWqYsgbOXn4wPILIFM59YYNsoNbwL1FaY='

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

usage() {
  sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'
}

split=()
for a in "$@"; do
  case "$a" in
  --*=*) split+=("${a%%=*}" "${a#*=}") ;;
  *) split+=("$a") ;;
  esac
done
set -- "${split[@]}"

V='' web_dir=ulrmm-web out=dist key_file='' prebuilt=''
while [ $# -gt 0 ]; do
  case "$1" in
  -h | --help)
    usage
    exit 0
    ;;
  --prebuilt) prebuilt=1 ;;
  --web-dir | --out | --key-file)
    [ $# -ge 2 ] || die "$1 needs a value."
    case "$1" in
    --web-dir) web_dir=$2 ;;
    --out) out=$2 ;;
    --key-file) key_file=$2 ;;
    esac
    shift
    ;;
  -*) die "unknown option $1" ;;
  *)
    [ -z "$V" ] || die "one version only."
    V=$1
    ;;
  esac
  shift
done

[[ $V =~ ^[0-9]+\.[0-9]{2}\.[0-9]{2}\.[0-9]{4}$ ]] || die "'${V:-}' is not a version like 2.27.10.2026."
repo=$(cd "$(dirname "$0")/../.." && pwd)
[ "$(tr -d '[:space:]' <"${repo}/VERSION")" = "$V" ] || die "${repo}/VERSION is not ${V}; the servers check the version they get."
[ -f "${web_dir}/package.json" ] || die "${web_dir} is not the dashboard checkout (--web-dir)."
[ -n "$key_file" ] || [ -n "${ULRMM_RELEASE_KEY:-}" ] || die "no signing key: --key-file or ULRMM_RELEASE_KEY."
[ -z "$key_file" ] || [ -r "$key_file" ] || die "cannot read ${key_file} (--key-file)."

commit=$(git -C "$repo" rev-parse HEAD)
web_commit=$(git -C "$web_dir" rev-parse HEAD)
server="ulrmm-server-${V}.tar.gz"
web="ulrmm-web-${V}.tar.gz"
mkdir -p "$out"
out=$(cd "$out" && pwd)

git -C "$repo" archive --format=tar.gz --prefix="ulrmm-server-${V}/" -o "${out}/${server}" HEAD

# npm install scripts run here: no signing key in their environment, even
# one the caller exported, and the key file is read only afterwards
[ -n "$prebuilt" ] || (unset ULRMM_RELEASE_KEY && cd "$web_dir" && npm ci && npm run build)
[ -f "${web_dir}/dist/index.html" ] || die "the dashboard build produced no dist/index.html."
tar -C "$web_dir" --transform "s,^dist,ulrmm-web-${V}/dist/spa," -czf "${out}/${web}" dist

[ -z "$key_file" ] || ULRMM_RELEASE_KEY=$(tr -d '[:space:]' <"$key_file")
[ -n "${ULRMM_RELEASE_KEY:-}" ] || die "no signing key: ${key_file} is empty."
export ULRMM_RELEASE_KEY

python3 - "$V" "$commit" "$web_commit" "$out" "$PUBKEY" "$server" "$web" <<'PY'
import base64, hashlib, json, os, sys
from datetime import datetime, timezone
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

v, commit, web_commit, out, pubkey, *names = sys.argv[1:]
seed = base64.b64decode(os.environ["ULRMM_RELEASE_KEY"])
if len(seed) != 32:
    sys.exit("ERROR: the signing key is not a 32 byte seed.")
key = Ed25519PrivateKey.from_private_bytes(seed)
pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
if base64.b64encode(pub).decode() != pubkey:
    sys.exit("ERROR: this key does not match the public key pinned in the servers.")
assets = []
for n in names:
    p = os.path.join(out, n)
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    assets.append({"name": n, "sha256": h.hexdigest(), "size": os.path.getsize(p)})
manifest = {
    "v": 1,
    "product": "ulrmm",
    "version": v,
    "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "commit": commit,
    "web_commit": web_commit,
    "assets": assets,
}
data = json.dumps(manifest, indent=2).encode() + b"\n"
with open(os.path.join(out, f"ulrmm-{v}.manifest.json"), "wb") as f:
    f.write(data)
with open(os.path.join(out, f"ulrmm-{v}.manifest.sig"), "w") as f:
    f.write(base64.b64encode(key.sign(data)).decode() + "\n")
PY

ls -l "${out}/ulrmm-server-${V}.tar.gz" "${out}/ulrmm-web-${V}.tar.gz" "${out}/ulrmm-${V}.manifest.json" "${out}/ulrmm-${V}.manifest.sig"
