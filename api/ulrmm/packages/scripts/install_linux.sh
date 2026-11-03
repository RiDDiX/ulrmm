#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

# install an uploaded .deb or .rpm as root. PKG_* env only.
# server reads the last line: ULRMM-PKG {json}.
#
# installer output goes to a file, so a daemon it starts cannot hold the
# agent's pipes. the download link is unset before anything runs.

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C DEBIAN_FRONTEND=noninteractive

url=${PKG_URL:-} sum=${PKG_SHA256:-} kind=${PKG_KIND:-} mode=${PKG_MODE:-} allow=${PKG_ALLOW_UNSIGNED:-}
# agent jobs hand over the file they downloaded and checked
pkgfile=${PKG_FILE:-}
unset PKG_URL PKG_SHA256 PKG_NAME PKG_KIND PKG_ARGS PKG_ALLOW_UNSIGNED PKG_MODE PKG_FILE PKG_DIR
tok=${url%/}
tok=${tok##*/}
result=fail code=null sig='' signer='' msg='the script stopped early' dir=''

# printable ascii without the link, capped, json-escaped
esc() {
    local s=$1
    [ -n "$url" ] && s=${s//"$url"/<url>}
    [ ${#tok} -ge 16 ] && s=${s//"$tok"/<token>}
    printf '%s' "$s" | tr '\000-\037' ' ' | tr -c ' -~' '?' | cut -c 1-400 | sed 's/[\\"]/\\&/g'
}
finish() {
    [ -n "$dir" ] && rm -rf "$dir"
    printf 'ULRMM-PKG {"result":"%s","exit":%s,"sig":"%s","signer":"%s","msg":"%s"}\n' \
        "$result" "$code" "$(esc "$sig")" "$(esc "$signer")" "$(esc "$msg")"
}
refuse() {
    result=refused msg=$*
    exit 1
}
fail() {
    result=fail msg=$*
    exit 1
}
trap finish EXIT
trap 'fail "the script was stopped"' HUP INT TERM

[ "$mode" = system ] || refuse "Linux packages install as root only"
[ "$(id -u)" = 0 ] || refuse "not running as root"
case $kind in
deb | rpm) ;;
*) refuse "not a Linux package kind: $kind" ;;
esac
sum=$(printf '%s' "$sum" | tr A-F a-f)
[[ $sum =~ ^[0-9a-f]{64}$ ]] || refuse "no valid sha256 was handed to the script"
if [ -n "$pkgfile" ]; then
    # root's own file in root's own folder, nobody can swap it before the run
    if [ "${pkgfile#/}" = "$pkgfile" ] || [ ! -f "$pkgfile" ] || [ -L "$pkgfile" ] ||
        [ ! -O "$pkgfile" ] || [ ! -O "${pkgfile%/*}" ]; then
        refuse "the package file is not a regular file owned by root"
    fi
else
    case $url in
    *[[:space:]\"\\]*) refuse "the download link has spaces, quotes or backslashes" ;;
    https://?*) ;;
    *) refuse "the download link is not https" ;;
    esac
fi

dir=$(mktemp -d /tmp/ulrmm-pkg.XXXXXX) || fail "cannot create a work directory"
file=${pkgfile:-$dir/package.$kind}
# pick the package tool before the download. wrong distro is not a bad signature.
case $kind in
deb)
    if command -v apt-get >/dev/null; then
        set -- apt-get install -y -o DPkg::Lock::Timeout=300 \
            -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold "$file"
    elif command -v dpkg >/dev/null; then
        set -- dpkg --force-confdef --force-confold -i "$file"
    else
        fail "no apt-get or dpkg on this system"
    fi
    ;;
rpm)
    if command -v dnf >/dev/null; then
        set -- dnf install -y "$file"
    elif command -v yum >/dev/null; then
        set -- yum install -y "$file"
    elif command -v zypper >/dev/null; then
        set -- zypper --non-interactive install "$file"
    else
        fail "no dnf, yum or zypper on this system"
    fi
    ;;
esac

# nginx does not log a ulrmm/* user agent. the link has the token, so it
# goes on stdin: every local user can read argv.
if [ -n "$pkgfile" ]; then
    :
elif command -v curl >/dev/null; then
    printf 'url = "%s"\n' "$url" |
        curl -K - -fsS --proto '=https' --retry 2 -A ulrmm/pkg -o "$file" 2>"$dir/err"
elif command -v wget >/dev/null; then
    # -q: wget's own messages would carry the link
    printf '%s\n' "$url" | wget -q --https-only --max-redirect=0 -U ulrmm/pkg -O "$file" -i -
else
    fail "neither curl nor wget is installed"
fi || fail "download failed (exit $?)$(sed -n '1s/^/: /p' "$dir/err" 2>/dev/null)"
[ "$(sha256sum "$file" | cut -d ' ' -f 1)" = "$sum" ] ||
    refuse "sha256 mismatch, the download is not the uploaded package"

if [ "$kind" = rpm ]; then
    out=$(rpm -K "$file" 2>&1)
    rc=$?
    out=${out#"$file:"}
    out=${out# }
    case $rc:$out in
    "0:digests signatures OK" | "0:signatures OK")
        sig=Valid
        key=$(rpm -Kv "$file" 2>/dev/null | sed -En 's/.*ignature, key (ID|fingerprint:) ([0-9a-f]+): OK$/\2/p' | head -n 1)
        signer=$(rpm -q --qf '%{SUMMARY}' "gpg-pubkey-$key" 2>/dev/null) || signer=''
        signer="${signer% public key}${key:+ (key $key)}"
        ;;
    "0:digests OK") sig=NotSigned ;;
    *)
        sig=Invalid
        refuse "rpm -K: $out"
        ;;
    esac
else
    sig=NotSigned
fi
[ "$sig" = NotSigned ] && [ "$allow" != 1 ] &&
    refuse "the package is not signed and unsigned packages are not allowed"
# zypper refuses unsigned rpms unless told
[ "$1" = zypper ] && [ "$sig" = NotSigned ] &&
    set -- zypper --non-interactive install --allow-unsigned-rpm "$file"

"$@" </dev/null >"$dir/out" 2>&1
code=$?
# failed install: refresh the lists and try again. a broken repo fails
# apt-get update; the retry still runs.
if [ "$code" != 0 ] && [ "$1" = apt-get ]; then
    { apt-get update; "$@"; } </dev/null >>"$dir/out" 2>&1
    code=$?
fi
tail -n 40 "$dir/out"
case $1:$code in
*:0) result=ok msg="installed with $1" ;;
zypper:102) result=reboot msg="installed with zypper, it asks for a reboot" ;;
zypper:106)
    # 106 wins over 107, so a failed package script only shows in the output
    grep -q 'scriptlet failed' "$dir/out" &&
        fail "zypper exited with 106 and a package script failed: $(grep 'scriptlet failed' "$dir/out" | tail -n 1)"
    result=ok msg="installed with zypper, a repository was skipped"
    ;;
*) fail "$1 exited with $code: $(tail -n 3 "$dir/out")" ;;
esac
