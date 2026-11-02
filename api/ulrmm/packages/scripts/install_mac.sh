#!/bin/bash
# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

# install an uploaded .pkg as root. PKG_* env only.
# server reads the last line: ULRMM-PKG {json}. bash 3.2.
#
# installer output goes to a file, so a daemon it starts cannot hold the
# agent's pipes. the download link is unset before anything runs.
# no /usr/local/bin in PATH: on Intel, Homebrew leaves that dir user-writable.

export PATH=/usr/bin:/bin:/usr/sbin:/sbin
export LC_ALL=C

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

[ "$mode" = system ] || refuse "macOS packages install as root only"
[ "$(id -u)" = 0 ] || refuse "not running as root"
[ "$kind" = pkg ] || refuse "not a macOS package kind: $kind"
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
file=${pkgfile:-$dir/package.pkg}
# nginx does not log a ulrmm/* user agent. the link has the token, so it
# goes on stdin, not in argv.
[ -n "$pkgfile" ] || printf 'url = "%s"\n' "$url" |
    curl -K - -fsS --proto '=https' --retry 2 -A ulrmm/pkg -o "$file" 2>"$dir/err" ||
    fail "download failed (exit $?)$(sed -n '1s/^/: /p' "$dir/err")"
[ "$(shasum -a 256 "$file" | cut -d ' ' -f 1)" = "$sum" ] ||
    refuse "sha256 mismatch, the download is not the uploaded package"

check=$(pkgutil --check-signature "$file" 2>&1)
rc=$?
status=$(printf '%s\n' "$check" | sed -n 's/^ *Status: //p' | head -n 1)
if [ "$status" = "no signature" ]; then
    sig=NotSigned
    [ "$allow" = 1 ] || refuse "the package is not signed and unsigned packages are not allowed"
else
    # with Gatekeeper off spctl accepts anything (override=security disabled)
    if gk=$(spctl --assess --type install -v "$file" 2>&1) && [ "$rc" = 0 ] &&
        ! printf '%s\n' "$gk" | grep -q '^override='; then
        sig=Valid
        signer=$(printf '%s\n' "$check" | sed -n 's/^ *1\. //p' | head -n 1)
    else
        sig=Rejected
        refuse "signature rejected: ${status:-unknown}; $(printf '%s\n' "$gk" | tail -n 2)"
    fi
fi

installer -pkg "$file" -target / </dev/null >"$dir/out" 2>&1
code=$?
tail -n 40 "$dir/out"
[ "$code" = 0 ] || fail "installer exited with $code: $(tail -n 3 "$dir/out")"
case $(installer -query RestartAction -pkg "$file" 2>/dev/null) in
*Restart* | *Shutdown*) result=reboot msg="installed, the package asks for a restart" ;;
*) result=ok msg="installed" ;;
esac
