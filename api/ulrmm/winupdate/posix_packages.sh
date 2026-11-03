#!/bin/sh
# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

# Package inventory, update scan and update install for Linux, macOS and FreeBSD agents.
#
# Usage: posix_packages.sh inventory | scan | refresh | install <guid> [<guid> ...] | remove <source> <target>
#
# Output is one tab separated record per line:
#   S source name version publisher size_bytes install_epoch location [source_name source_version]
#   U manager name arch current new severity category advisory summary
#   R 0|1
#   I guid exitcode message
#   E manager message
#   J BEGIN ... J END (raw system_profiler JSON on macOS)
#   A BEGIN ... A END (raw pkg audit JSON on FreeBSD)
#
# E lines keyed by a plain manager name mean its update list is incomplete.
# Other keys (apt-update, <manager>-refresh, <manager>-inventory, dpkg, ...)
# are warnings that do not affect the update list.
#
# Exit codes: 0 ok, 2 no supported package manager, 3 invalid arguments.

export LC_ALL=C LANG=C
# runs as root: system directories only, /usr/local and Homebrew paths can be user writable
PATH=/usr/sbin:/usr/bin:/sbin:/bin
OS=$(uname -s)
# pkg lives in /usr/local/sbin, and /usr/local belongs to root on FreeBSD
[ "$OS" = FreeBSD ] && PATH=$PATH:/usr/local/sbin:/usr/local/bin
export PATH
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a APT_LISTCHANGES_FRONTEND=none
export ZYPP_LOCK_TIMEOUT=120
umask 022

TAB=$(printf '\t')
MODE=$1
[ $# -gt 0 ] && shift

usage() {
    printf 'E\tscript\tusage: %s inventory|scan|refresh|install <guid>...|remove <source> <target>\n' "${0##*/}"
    exit 3
}

has() {
    command -v "$1" >/dev/null 2>&1
}

err() {
    printf 'E\t%s\t%s\n' "$1" "$2"
}

# the same markers as the agent
is_truenas() {
    [ -e /data/manifest.json ] && [ -e /usr/bin/midclt ]
}

# last meaningful line of the first non-empty file, tabs removed
lastmsg() {
    for f in "$@"; do
        if [ -s "$f" ]; then
            tr '\t\r' '  ' <"$f" | awk '
                NF { l = $0 }
                /^(E: |W: Failed to fetch|Error|error|ERROR|WARNING)/ { e = $0 }
                END { if (e != "") l = e; sub(/^ +/, "", l); print substr(l, 1, 500) }'
            return
        fi
    done
}

valid_guid() {
    case $1 in *:*:*:*) ;; *) return 1 ;; esac
    g_m=${1%%:*}
    g_r=${1#*:}
    g_n=${g_r%%:*}
    g_r=${g_r#*:}
    g_a=${g_r%%:*}
    g_v=${g_r#*:}
    case $g_m in
    apt | dnf | yum | zypper | pacman | apk | flatpak | snap | brew | brew-cask | pkg)
        case $g_n in '' | -* | *[!A-Za-z0-9._+@~-]*) return 1 ;; esac
        ;;
    softwareupdate)
        case $g_n in '' | -* | ' '* | *[!A-Za-z0-9._+@~,"() "-]*) return 1 ;; esac
        ;;
    *) return 1 ;;
    esac
    case $g_a in *[!A-Za-z0-9_]*) return 1 ;; esac
    case $g_v in *[!A-Za-z0-9._+~:^,-]*) return 1 ;; esac
    return 0
}

valid_remove_name() {
    [ ${#1} -le 255 ] || return 1
    case $1 in '' | -* | *[!A-Za-z0-9._+@~-]*) return 1 ;; esac
}

valid_remove_target() {
    r_source=$1
    r_target=$2
    case $OS:$r_source in
    Linux:dpkg)
        case $r_target in
        *:*)
            r_name=${r_target%:*}
            r_arch=${r_target##*:}
            valid_remove_name "$r_name" || return 1
            case $r_arch in '' | [!A-Za-z0-9]* | *[!A-Za-z0-9_-]*) return 1 ;; esac
            ;;
        *) valid_remove_name "$r_target" || return 1 ;;
        esac
        ;;
    Linux:rpm | Linux:pacman | Linux:apk | Linux:flatpak | Linux:snap | Darwin:brew | Darwin:brew-cask | FreeBSD:pkg)
        valid_remove_name "$r_target" || return 1
        ;;
    Darwin:app)
        [ ${#r_target} -le 1024 ] || return 1
        case $r_target in /Applications/*.app) ;; *) return 1 ;; esac
        r_name=${r_target#/Applications/}
        r_name=${r_name%.app}
        case $r_name in '' | .* | */*) return 1 ;; esac
        case $r_name in *[[:cntrl:]]*) return 1 ;; esac
        ;;
    *) return 1 ;;
    esac
    return 0
}

case $MODE in
inventory | scan | refresh)
    [ $# -eq 0 ] || usage
    ;;
install)
    [ $# -gt 0 ] || usage
    for g in "$@"; do
        if ! valid_guid "$g"; then
            printf 'E\tscript\tinvalid guid: %s\n' "$(printf '%s' "$g" | tr -d '\t\r\n' | cut -c 1-200)"
            exit 3
        fi
    done
    ;;
remove)
    [ $# -eq 2 ] || usage
    if ! valid_remove_target "$1" "$2"; then
        printf 'E\tscript\tinvalid remove target: %s:%s\n' \
            "$(printf '%s' "$1" | tr -d '\t\r\n' | cut -c 1-40)" \
            "$(printf '%s' "$2" | tr -d '\t\r\n' | cut -c 1-200)"
        exit 3
    fi
    ;;
*)
    usage
    ;;
esac

APT= DNF= RPM= ZYPPER= PACMAN= APK= FLATPAK= SNAP=
BREW= BREW_USER= SWU= PKG=
if [ "$OS" = FreeBSD ]; then
    # /usr/sbin/pkg only offers to bootstrap the real one
    [ -x /usr/local/sbin/pkg ] && PKG=/usr/local/sbin/pkg
elif [ "$OS" != Darwin ]; then
    has apt-get && has dpkg-query && APT=1
    if has dnf; then
        DNF=dnf
    elif has yum; then
        DNF=yum
    fi
    has rpm && RPM=1
    has zypper && ZYPPER=1
    has pacman && PACMAN=1
    has apk && APK=1
    has flatpak && FLATPAK=1
    has snap && SNAP=1
else
    for b in /opt/homebrew/bin/brew /usr/local/bin/brew; do
        if [ -x "$b" ]; then
            BREW=$b
            BREW_USER=$(stat -f %Su "$b" 2>/dev/null)
            break
        fi
    done
    has softwareupdate && SWU=1
fi

if [ -z "$APT$DNF$ZYPPER$PACMAN$APK$FLATPAK$SNAP$BREW$SWU$PKG" ] &&
    [ "$OS" != Darwin ] && [ "$MODE" != remove ] && ! is_truenas; then
    err none "no supported package manager found"
    exit 2
fi

T=$(mktemp -d "${TMPDIR:-/tmp}/ulrmmpkg.XXXXXX") || {
    err script "cannot create temp dir"
    exit 1
}
trap 'rm -rf "$T"' EXIT
trap 'exit 1' HUP INT TERM

# ---------------------------------------------------------------- inventory

inv_dpkg() {
    stat -c "%Y$TAB%n" /var/lib/dpkg/info/*.list >"$T/lists" 2>/dev/null
    if ! dpkg-query -W -f='${db:Status-Abbrev}\t${binary:Package}\t${Version}\t${Maintainer}\t${Installed-Size}\t${source:Package}\t${source:Version}\n' >"$T/out" 2>"$T/err"; then
        err dpkg "$(lastmsg "$T/err")"
        return
    fi
    awk -F '\t' -v OFS='\t' '
        FILENAME == ARGV[1] { n = $2; sub(/.*\//, "", n); sub(/\.list$/, "", n); t[n] = $1; next }
        $1 ~ /^[ih]i/ {
            sz = ($5 ~ /^[0-9]+$/) ? sprintf("%.0f", $5 * 1024) : ""
            print "S", "dpkg", $2, $3, $4, sz, t[$2], "", $6, $7
        }' "$T/lists" "$T/out"
}

inv_rpm() {
    if ! rpm -qa --qf '%{NAME}\t%|EPOCH?{%{EPOCH}:}:{}|%{VERSION}-%{RELEASE}\t%{VENDOR}\t%{SIZE}\t%{INSTALLTIME}\t%{SOURCERPM}\n' >"$T/out" 2>"$T/err"; then
        err rpm "$(lastmsg "$T/err")"
        return
    fi
    # SOURCERPM is name-version-release.src.rpm. epoch comes from the binary
    awk -F '\t' -v OFS='\t' '
        $1 != "" && $1 != "gpg-pubkey" {
            if ($3 == "(none)") $3 = ""
            if ($4 !~ /^[0-9]+$/) $4 = ""
            if ($5 !~ /^[0-9]+$/) $5 = ""
            sn = sv = ""
            if ($6 ~ /-[^-]+-[^-]+\.(no)?src\.rpm$/) {
                sn = $6
                sub(/\.(no)?src\.rpm$/, "", sn)
                sv = sn
                sub(/-[^-]+-[^-]+$/, "", sn)
                sv = substr(sv, length(sn) + 2)
                if (match($2, /^[0-9]+:/)) sv = substr($2, 1, RLENGTH) sv
            }
            print "S", "rpm", $1, $2, $3, $4, $5, "", sn, sv
        }' "$T/out"
}

pacman_db() {
    p_db=$(pacman-conf DBPath 2>/dev/null)
    [ -n "$p_db" ] || p_db=/var/lib/pacman/
    p_db=${p_db%/}
}

inv_pacman() {
    pacman_db
    set -- "$p_db"/local/*/desc
    if [ ! -f "$1" ]; then
        err pacman-inventory "no local package database in $p_db"
        return
    fi
    awk -v OFS='\t' '
        function flush() {
            if (n != "") print "S", "pacman", n, v, p, s, d, ""
            n = v = p = s = d = k = ""
        }
        FNR == 1 { flush() }
        /^%[A-Z0-9]+%$/ { k = $0; next }
        $0 == "" { k = ""; next }
        k == "%NAME%" { n = $0 }
        k == "%VERSION%" { v = $0 }
        k == "%PACKAGER%" { p = $0 }
        k == "%SIZE%" { s = $0 }
        k == "%INSTALLDATE%" { d = $0 }
        END { flush() }' "$@"
}

inv_apk() {
    if [ ! -f /lib/apk/db/installed ]; then
        err apk-inventory "no /lib/apk/db/installed"
        return
    fi
    awk -v OFS='\t' '
        function flush() {
            if (n != "") print "S", "apk", n, v, m, s, "", "", o, (o != "" ? v : "")
            n = v = m = s = o = ""
        }
        /^P:/ { n = substr($0, 3) }
        /^o:/ { o = substr($0, 3) }
        /^V:/ { v = substr($0, 3) }
        /^m:/ { m = substr($0, 3) }
        /^I:/ { s = substr($0, 3) }
        $0 == "" { flush() }
        END { flush() }' /lib/apk/db/installed
}

inv_flatpak() {
    if ! flatpak list --app --columns=application,version,origin >"$T/out" 2>"$T/err" </dev/null; then
        err flatpak-inventory "$(lastmsg "$T/err")"
        return
    fi
    awk -F '\t' -v OFS='\t' 'NF >= 1 && $1 != "" { print "S", "flatpak", $1, $2, $3, "", "", "" }' "$T/out"
}

inv_snap() {
    if ! snap list >"$T/out" 2>"$T/err" </dev/null; then
        err snap-inventory "$(lastmsg "$T/err" "$T/out")"
        return
    fi
    awk -v OFS='\t' '
        NR > 1 && NF >= 5 { p = $5; gsub(/[^A-Za-z0-9._-]/, "", p); print "S", "snap", $1, $2, p, "", "", "" }' "$T/out"
}

# brew_run <seconds> args: brew belongs to a non-root user, so it runs as that
# user and is stopped (TERM, then KILL) when it exceeds the time limit
brew_run() {
    b_limit=$1
    shift
    (cd / && exec sudo -u "$BREW_USER" -H env HOMEBREW_NO_AUTO_UPDATE=1 NONINTERACTIVE=1 \
        HOMEBREW_NO_ANALYTICS=1 HOMEBREW_NO_ENV_HINTS=1 HOMEBREW_NO_INSTALL_CLEANUP=1 \
        PATH="${BREW%/brew}:/usr/bin:/bin:/usr/sbin:/sbin" "$BREW" "$@") </dev/null &
    b_pid=$!
    rm -f "$T/brew_timeout"
    (
        i=0
        while [ $i -lt "$b_limit" ]; do
            sleep 1
            kill -0 "$b_pid" 2>/dev/null || exit 0
            i=$((i + 1))
        done
        : >"$T/brew_timeout"
        kill -TERM "$b_pid"
        sleep 10
        kill -KILL "$b_pid"
    ) >/dev/null 2>&1 </dev/null &
    b_watch=$!
    wait "$b_pid"
    b_rc=$?
    kill "$b_watch" 2>/dev/null
    if [ -e "$T/brew_timeout" ]; then
        echo "Error: brew $1 timed out after ${b_limit}s" >&2
        [ $b_rc -eq 0 ] && b_rc=124
    fi
    return $b_rc
}

# brew_ok [error keys]
brew_ok() {
    case $BREW_USER in
    '' | root)
        for k in "$@"; do
            err "$k" "brew is owned by root or owner unknown, skipped"
        done
        return 1
        ;;
    esac
    return 0
}

inv_brew() {
    brew_ok brew-inventory || return
    for kind in formula cask; do
        src=brew
        [ $kind = cask ] && src=brew-cask
        if brew_run 120 list --versions --$kind >"$T/out" 2>"$T/err"; then
            awk -v OFS='\t' -v src=$src 'NF >= 2 { print "S", src, $1, $NF, "", "", "", "" }' "$T/out"
        else
            err $src-inventory "$(lastmsg "$T/err")"
        fi
    done
}

inv_macos_apps() {
    if system_profiler -json SPApplicationsDataType >"$T/sp" 2>"$T/err" </dev/null; then
        printf 'J\tBEGIN\n'
        cat "$T/sp"
        printf '\nJ\tEND\n'
    else
        err system_profiler "$(lastmsg "$T/err")"
    fi
}

inv_pkg() {
    if ! "$PKG" query '%n\t%v\t%m\t%sb\t%t' >"$T/out" 2>"$T/err" </dev/null; then
        err pkg-inventory "$(lastmsg "$T/err")"
        return
    fi
    awk -F '\t' -v OFS='\t' '$1 != "" { print "S", "pkg", $1, $2, $3, $4, $5, "" }' "$T/out"
}

inventory() {
    [ -n "$PKG" ] && inv_pkg
    if [ -n "$APT" ]; then
        inv_dpkg
    elif [ -n "$RPM" ] && [ -n "$DNF$ZYPPER" ]; then
        inv_rpm
    fi
    [ -n "$PACMAN" ] && inv_pacman
    [ -n "$APK" ] && inv_apk
    [ -n "$FLATPAK" ] && inv_flatpak
    [ -n "$SNAP" ] && inv_snap
    [ "$OS" = Darwin ] && inv_macos_apps
    [ -n "$BREW" ] && inv_brew
}

# ---------------------------------------------------------------------- scan

# apt-get update exits 0 when indexes fail to download, so check the warnings too
apt_update() {
    if ! apt-get -q -o DPkg::Lock::Timeout="$1" update >"$T/out" 2>"$T/err" </dev/null ||
        grep -q '^W: Failed to fetch' "$T/err"; then
        err apt-update "apt-get update failed: $(lastmsg "$T/err" "$T/out")"
    fi
}

scan_apt() {
    apt_update 120
    if ! apt-get -s -q -o Debug::NoLocking=1 --with-new-pkgs upgrade >"$T/out" 2>"$T/err" </dev/null; then
        err apt "upgrade simulation failed: $(lastmsg "$T/err" "$T/out")"
        return
    fi
    # Inst name [cur] (new Origin:Version/suite, Origin:Version/suite [arch])
    awk -v OFS='\t' '
        /^Inst / {
            name = $2
            rest = $0
            sub(/^Inst [^ ]+ /, "", rest)
            if (substr(rest, 1, 1) != "[") next
            cur = substr(rest, 2)
            sub(/\].*/, "", cur)
            sub(/^\[[^]]*\] \(/, "", rest)
            sub(/\)[^)]*$/, "", rest)
            arch = rest
            sub(/.*\[/, "", arch)
            sub(/\].*/, "", arch)
            sub(/ *\[[^]]*\]$/, "", rest)
            new = rest
            sub(/ .*/, "", new)
            rel = ""
            if (index(rest, " ")) { rel = rest; sub(/^[^ ]+ /, "", rel) }
            sev = ""
            cnt = split(rel, rs, ", ")
            cat = (cnt > 0) ? rs[1] : ""
            for (i = 1; i <= cnt; i++)
                if (rs[i] ~ /-security|Debian-Security/) { sev = "Important"; cat = rs[i] }
            sub(/^[^\/]*\//, "", cat)
            sub(/:.*/, "", name)
            if (new == "") next
            print "U", "apt", name, arch, cur, new, sev, cat, "", ""
        }' "$T/out"
}

scan_dnf() {
    refresh=
    [ "$DNF" = dnf ] && refresh=--refresh
    rpm -qa --qf '%{NAME}.%{ARCH}\t%|EPOCH?{%{EPOCH}:}:{}|%{VERSION}-%{RELEASE}\n' >"$T/rpmq" 2>/dev/null
    $DNF -q $refresh check-update >"$T/out" 2>"$T/err" </dev/null
    rc=$?
    case $rc in
    0 | 100) ;;
    *)
        err $DNF "check-update failed ($rc): $(lastmsg "$T/err" "$T/out")"
        return
        ;;
    esac
    $DNF -q updateinfo list >"$T/ui" 2>/dev/null </dev/null || : >"$T/ui"
    awk -v OFS='\t' -v m=$DNF '
        function rank(s) {
            return s == "Critical" ? 4 : s == "Important" ? 3 : s == "Moderate" ? 2 : s == "Low" ? 1 : 0
        }
        function catrank(c) {
            return c == "security" ? 3 : c == "bugfix" ? 2 : c == "enhancement" ? 1 : 0
        }
        FILENAME == ARGV[1] { cur[$1] = $2; next }
        FILENAME == ARGV[2] {
            if (NF < 3) next
            adv = $1
            nevra = ""
            sev = ""
            type = ""
            if ($2 ~ /\/Sec\.$/) {
                # dnf4/yum: ADVISORY Severity/Sec. NEVRA
                type = "security"
                sev = $2
                sub(/\/Sec\.$/, "", sev)
                nevra = $3
            } else if ($2 ~ /^(bugfix|enhancement|newpackage|security|unspecified|unknown)$/) {
                type = $2
                for (i = 3; i <= NF; i++)
                    if ($i ~ /-[^-]+-[^-]+\.[A-Za-z0-9_]+$/) { nevra = $i; break }
                # dnf5: ADVISORY type severity NEVRA date time
                if (i == 4) sev = $3
            } else next
            if (nevra == "") next
            if (type == "security" && rank(sev) == 0) sev = "Low"
            if (type != "security") sev = ""
            arch = nevra
            sub(/.*\./, "", arch)
            name = nevra
            sub(/\.[^.]*$/, "", name)
            sub(/-[^-]*-[^-]*$/, "", name)
            key = name "." arch
            if (rank(sev) > rank(usev[key])) usev[key] = sev
            if (catrank(type) > catrank(ucat[key])) ucat[key] = type
            if (index("," uadv[key] ",", "," adv ",") == 0)
                uadv[key] = (uadv[key] == "") ? adv : uadv[key] "," adv
            next
        }
        /^Obsoleting/ { stop = 1 }
        stop { next }
        NF == 1 && hold == "" && $1 ~ /\./ { hold = $1; next }
        {
            if (hold != "") { $0 = hold " " $0; hold = "" }
            if (NF != 3 || $1 !~ /\.[A-Za-z0-9_]+$/ || $2 !~ /-/) next
            arch = $1
            sub(/.*\./, "", arch)
            name = $1
            sub(/\.[^.]*$/, "", name)
            print "U", m, name, arch, cur[$1], $2, usev[$1], ucat[$1], uadv[$1], ""
        }' "$T/rpmq" "$T/ui" "$T/out"
}

scan_zypper() {
    if ! zypper -n -q refresh >"$T/out" 2>"$T/err" </dev/null; then
        err zypper-refresh "refresh failed: $(lastmsg "$T/err" "$T/out")"
    fi
    zypper -n -q list-updates >"$T/lu" 2>"$T/err" </dev/null
    rc=$?
    # see the exit codes in install_guids
    case $rc in
    0 | 100 | 101 | 102 | 103 | 106) ;;
    *)
        err zypper "list-updates failed ($rc): $(lastmsg "$T/err" "$T/lu")"
        return
        ;;
    esac
    zypper -n -q list-patches --category security >"$T/lp" 2>/dev/null </dev/null
    awk -F '|' '
        function trim(s) { gsub(/^ +| +$/, "", s); return s }
        !hdr && NF >= 3 {
            for (i = 1; i <= NF; i++) col[trim($i)] = i
            if ("Name" in col) hdr = 1
            next
        }
        hdr && NF >= 3 {
            if (("Status" in col) && trim($col["Status"]) != "needed") next
            n = trim($col["Name"])
            if (n ~ /^[A-Za-z0-9._:+-]+$/) print n
        }' "$T/lp" >"$T/lpn"
    : >"$T/pi"
    if [ -s "$T/lpn" ]; then
        set -f
        # shellcheck disable=SC2046
        zypper -n -q info -t patch $(cat "$T/lpn") >"$T/pi" 2>/dev/null </dev/null
        set +f
    fi
    awk -F '|' -v OFS='\t' '
        function trim(s) { gsub(/^ +| +$/, "", s); return s }
        function rank(s) {
            return s == "Critical" ? 4 : s == "Important" ? 3 : s == "Moderate" ? 2 : s == "Low" ? 1 : 0
        }
        FILENAME == ARGV[1] {
            if ($0 ~ /^Information for patch /) { adv = ""; sev = ""; inc = 0; next }
            if ($0 !~ /^[ \t]/) inc = 0
            if ($0 ~ /^Name *:/) { adv = $0; sub(/^Name *: */, "", adv) }
            else if ($0 ~ /^Severity *:/) {
                sev = $0
                sub(/^Severity *: */, "", sev)
                sev = toupper(substr(sev, 1, 1)) tolower(substr(sev, 2))
                if (rank(sev) == 0) sev = "Low"
            } else if ($0 ~ /^Conflicts *:/) inc = 1
            else if (inc && $0 ~ /^[ \t]+[^ ]+ < /) {
                split(trim($0), c, " ")
                key = c[1]
                if (key ~ /^srcpackage:/) next
                if (rank(sev) > rank(usev[key])) usev[key] = sev
                if (index("," uadv[key] ",", "," adv ",") == 0)
                    uadv[key] = (uadv[key] == "") ? adv : uadv[key] "," adv
            }
            next
        }
        !hdr && NF >= 5 {
            for (i = 1; i <= NF; i++) col[trim($i)] = i
            if (("Name" in col) && ("Available Version" in col)) hdr = 1
            next
        }
        hdr && NF >= 5 {
            if (trim($1) != "v") next
            name = trim($col["Name"])
            arch = trim($col["Arch"])
            key = name "." arch
            cat = (usev[key] != "") ? "security" : trim($col["Repository"])
            print "U", "zypper", name, arch, trim($col["Current Version"]), trim($col["Available Version"]), usev[key], cat, uadv[key], ""
        }' "$T/pi" "$T/lu"
}

scan_pacman() {
    pacman_db
    if ! mkdir -p "$T/pdb/sync" || ! ln -s "$p_db/local" "$T/pdb/local"; then
        err pacman "cannot prepare a temporary package database"
        return
    fi
    cp -p "$p_db"/sync/*.db "$T/pdb/sync/" 2>/dev/null
    chmod 755 "$T"
    if id alpm >/dev/null 2>&1; then
        chown -R alpm "$T/pdb/sync" 2>/dev/null
    fi
    if ! pacman -Sy --dbpath "$T/pdb" --logfile /dev/null >"$T/out" 2>"$T/err" </dev/null; then
        err pacman "database sync failed: $(lastmsg "$T/err" "$T/out")"
        return
    fi
    # -Qu also exits 1 when nothing is outdated
    if ! pacman -Qu --dbpath "$T/pdb" >"$T/out" 2>"$T/err" </dev/null && grep -q '^error:' "$T/err"; then
        err pacman "pacman -Qu failed: $(lastmsg "$T/err")"
        return
    fi
    pacman -Sup --dbpath "$T/pdb" --logfile /dev/null --print-format '%n %a %r' >"$T/sup" 2>/dev/null </dev/null
    awk -v OFS='\t' '
        FILENAME == ARGV[1] { if (NF == 3) { arch[$1] = $2; repo[$1] = $3 }; next }
        NF >= 4 && $3 == "->" && $0 !~ /\[ignored\]/ {
            print "U", "pacman", $1, arch[$1], $2, $4, "", repo[$1], "", ""
        }' "$T/sup" "$T/out"
}

scan_apk() {
    if ! apk update >"$T/out" 2>"$T/err" </dev/null; then
        err apk-refresh "apk update failed: $(lastmsg "$T/err" "$T/out")"
    fi
    if ! apk list -u >"$T/out" 2>"$T/err" </dev/null; then
        err apk "apk list failed: $(lastmsg "$T/err" "$T/out")"
        return
    fi
    # name-newver-rN arch {origin} (license) [upgradable from: name-oldver-rN]
    awk -v OFS='\t' '
        /\[upgradable from: / {
            name = $1
            sub(/-[^-]*-r[0-9]+$/, "", name)
            new = substr($1, length(name) + 2)
            old = $0
            sub(/.*\[upgradable from: /, "", old)
            sub(/\].*/, "", old)
            old = substr(old, length(name) + 2)
            print "U", "apk", name, $2, old, new, "", "", "", ""
        }' "$T/out"
}

scan_flatpak() {
    flatpak list --app --columns=application,version,active >"$T/fl" 2>/dev/null </dev/null
    if ! flatpak remote-ls --updates --app --columns=application,arch,version,commit,origin >"$T/out" 2>"$T/err" </dev/null; then
        err flatpak "remote-ls failed: $(lastmsg "$T/err" "$T/out")"
        return
    fi
    awk -F '\t' -v OFS='\t' '
        FILENAME == ARGV[1] { cur[$1] = ($2 != "") ? $2 : substr($3, 1, 12); next }
        $1 != "" {
            new = ($3 != "") ? $3 : substr($4, 1, 12)
            print "U", "flatpak", $1, $2, cur[$1], new, "", $5, "", ""
        }' "$T/fl" "$T/out"
}

scan_snap() {
    snap list >"$T/sl" 2>/dev/null </dev/null
    if ! snap refresh --list >"$T/out" 2>"$T/err" </dev/null; then
        err snap "refresh --list failed: $(lastmsg "$T/err" "$T/out")"
        return
    fi
    awk -v OFS='\t' '
        FILENAME == ARGV[1] { if (FNR > 1) cur[$1] = $2; next }
        FNR > 1 && NF >= 3 { print "U", "snap", $1, "", cur[$1], $2, "", "", "", "" }' "$T/sl" "$T/out"
}

scan_brew() {
    brew_ok brew brew-cask || return
    if ! brew_run 120 update --quiet >"$T/out" 2>"$T/err"; then
        err brew-refresh "brew update failed: $(lastmsg "$T/err" "$T/out")"
    fi
    for kind in formula cask; do
        m=brew
        [ $kind = cask ] && m=brew-cask
        if ! brew_run 120 outdated --$kind --verbose >"$T/out" 2>"$T/err"; then
            err $m "brew outdated failed: $(lastmsg "$T/err" "$T/out")"
            continue
        fi
        # name (cur[, cur2]) < new   or   name (cur) != new
        awk -v OFS='\t' -v m=$m '
            $0 ~ /\[pinned at / { next }
            NF >= 4 && $2 ~ /^\(/ {
                cur = $0
                sub(/\).*/, "", cur)
                sub(/.*[(, ]/, "", cur)
                new = $0
                sub(/.*(<|!=) /, "", new)
                sub(/ .*/, "", new)
                print "U", m, $1, "", cur, new, "", "Homebrew", "", ""
            }' "$T/out"
    done
}

scan_softwareupdate() {
    softwareupdate -l >"$T/out" 2>&1 </dev/null
    rc=$?
    if [ $rc -ne 0 ]; then
        err softwareupdate "softwareupdate -l failed ($rc): $(lastmsg "$T/out")"
        return
    fi
    # * Label: <label>
    #     Title: <title>, Version: <ver>, Size: <n>KiB, Recommended: YES, Action: restart,
    awk -v OFS='\t' '
        function val(s, k,    i, v) {
            i = index(s, k ": ")
            if (i == 0) return ""
            v = substr(s, i + length(k) + 2)
            if (k == "Title" && index(v, ", Version: ")) return substr(v, 1, index(v, ", Version: ") - 1)
            if (index(v, ",")) v = substr(v, 1, index(v, ",") - 1)
            return v
        }
        /^[ \t]*\* Label: / { label = $0; sub(/^[ \t]*\* Label: /, "", label); next }
        label != "" && /Title: / {
            sev = (val($0, "Recommended") == "YES") ? "Important" : ""
            print "U", "softwareupdate", label, "", "", val($0, "Version"), sev, "macOS", "", val($0, "Title")
            label = ""
        }' "$T/out"
}

# name-version  <  needs updating (remote has new); versions hold no "-"
scan_pkg() {
    if ! "$PKG" update -q >"$T/out" 2>"$T/err" </dev/null; then
        err pkg-refresh "pkg update failed: $(lastmsg "$T/err" "$T/out")"
    fi
    if ! "$PKG" version -U -vRl '<' >"$T/out" 2>"$T/err" </dev/null; then
        err pkg "pkg version failed: $(lastmsg "$T/err" "$T/out")"
        return
    fi
    awk -v OFS='\t' '
        $2 == "<" && /remote has / {
            name = $1
            sub(/-[^-]*$/, "", name)
            cur = substr($1, length(name) + 2)
            new = $0
            sub(/.*remote has /, "", new)
            sub(/\).*/, "", new)
            if (name != "" && new != "") print "U", "pkg", name, "", cur, new, "", "", "", ""
        }' "$T/out"
}

# vulnerable installed packages from VuXML, as JSON
audit_pkg() {
    # exit 1 means vulnerable packages were found; -F reports the
    # vuln.xml download on stdout before the one JSON line
    "$PKG" audit -F -Rjson-compact >"$T/audit" 2>"$T/err" </dev/null
    if grep '^{' "$T/audit" >"$T/aj"; then
        printf 'A\tBEGIN\n'
        cat "$T/aj"
        printf 'A\tEND\n'
    else
        err pkg-audit "pkg audit failed: $(lastmsg "$T/err" "$T/audit")"
    fi
}

scan() {
    if [ -n "$PKG" ]; then
        scan_pkg
        audit_pkg
    fi
    [ -n "$APT" ] && scan_apt
    [ -n "$DNF" ] && scan_dnf
    [ -n "$ZYPPER" ] && scan_zypper
    [ -n "$PACMAN" ] && scan_pacman
    [ -n "$APK" ] && scan_apk
    [ -n "$FLATPAK" ] && scan_flatpak
    [ -n "$SNAP" ] && scan_snap
    [ -n "$SWU" ] && scan_softwareupdate
    [ -n "$BREW" ] && scan_brew
}

reboot_line() {
    r=0
    if [ -e /var/run/reboot-required ] || [ -e /run/reboot-required ]; then
        r=1
    elif [ "$OS" = FreeBSD ]; then
        # an installed kernel that is not the running one
        [ "$(freebsd-version -k 2>/dev/null)" != "$(freebsd-version -r 2>/dev/null)" ] && r=1
    elif [ "$OS" != Darwin ] && has needs-restarting; then
        needs-restarting -r >/dev/null 2>&1 </dev/null
        [ $? -eq 1 ] && r=1
    fi
    [ -n "$MAC_RESTART" ] && r=1
    printf 'R\t%s\n' "$r"
}

# ------------------------------------------------------------------- install

# print one I line per guid in $1 (space separated) for the last command
results() {
    if [ "$2" -eq 0 ]; then
        msg=ok
    else
        msg=$(lastmsg "$T/err" "$T/out")
    fi
    set -f
    for g in $1; do
        printf 'I\t%s\t%s\t%s\n' "$g" "$2" "$msg"
    done
    set +f
}

missing() {
    set -f
    for g in $1; do
        printf 'I\t%s\t127\t%s is not available\n' "$g" "$2"
    done
    set +f
}

install_guids() {
    apt_g= apt_p= dnf_g= dnf_p= zyp_g= zyp_p= pac_g= apk_g= apk_p=
    fp_g= fp_p= snap_g= snap_p= bf_g= bf_p= bc_g= bc_p= swu_g= pkg_g= pkg_p=
    native=
    [ -n "$APT" ] && native=$(dpkg --print-architecture 2>/dev/null)
    for g in "$@"; do
        m=${g%%:*}
        r=${g#*:}
        n=${r%%:*}
        r=${r#*:}
        a=${r%%:*}
        case $m in
        apt)
            [ -n "$a" ] && [ "$a" != all ] && [ "$a" != "$native" ] && n=$n:$a
            apt_g="$apt_g $g" apt_p="$apt_p $n"
            ;;
        dnf | yum)
            [ -n "$a" ] && n=$n.$a
            dnf_g="$dnf_g $g" dnf_p="$dnf_p $n"
            ;;
        zypper) zyp_g="$zyp_g $g" zyp_p="$zyp_p $n" ;;
        pacman) pac_g="$pac_g $g" ;;
        apk) apk_g="$apk_g $g" apk_p="$apk_p $n" ;;
        flatpak) fp_g="$fp_g $g" fp_p="$fp_p $n" ;;
        snap) snap_g="$snap_g $g" snap_p="$snap_p $n" ;;
        pkg) pkg_g="$pkg_g $g" pkg_p="$pkg_p $n" ;;
        brew) bf_g="$bf_g $g" bf_p="$bf_p $n" ;;
        brew-cask) bc_g="$bc_g $g" bc_p="$bc_p $n" ;;
        softwareupdate)
            swu_g="$swu_g
$g"
            ;;
        esac
    done

    set -f
    if [ -n "$apt_g" ]; then
        if [ -n "$APT" ]; then
            apt_update 600
            apt-get -y -q -o DPkg::Lock::Timeout=600 -o Dpkg::Options::=--force-confdef \
                -o Dpkg::Options::=--force-confold install --only-upgrade -- $apt_p >"$T/out" 2>"$T/err" </dev/null
            results "$apt_g" $?
        else
            missing "$apt_g" apt
        fi
    fi
    if [ -n "$dnf_g" ]; then
        if [ -n "$DNF" ]; then
            # dnf5 rejects "--"; names are validated not to start with "-"
            $DNF -y -q upgrade $dnf_p >"$T/out" 2>"$T/err" </dev/null
            results "$dnf_g" $?
        else
            missing "$dnf_g" dnf
        fi
    fi
    if [ -n "$zyp_g" ]; then
        if [ -n "$ZYPPER" ]; then
            zypper -n -q update -l -- $zyp_p >"$T/out" 2>"$T/err" </dev/null
            rc=$?
            # informational: 100 updates needed, 101 security updates, 102 reboot needed,
            # 103 restart zypper, 106 repos skipped; 104, 105 and 107 are failures
            case $rc in 100 | 101 | 102 | 103 | 106) rc=0 ;; esac
            results "$zyp_g" $rc
        else
            missing "$zyp_g" zypper
        fi
    fi
    if [ -n "$pac_g" ]; then
        if [ -n "$PACMAN" ]; then
            # partial upgrades are unsupported on Arch, always do a full upgrade
            pacman -Syu --noconfirm >"$T/out" 2>"$T/err" </dev/null
            results "$pac_g" $?
        else
            missing "$pac_g" pacman
        fi
    fi
    if [ -n "$apk_g" ]; then
        if [ -n "$APK" ]; then
            apk update >"$T/out" 2>"$T/err" </dev/null ||
                err apk-refresh "apk update failed: $(lastmsg "$T/err" "$T/out")"
            apk upgrade --no-progress -- $apk_p >"$T/out" 2>"$T/err" </dev/null
            results "$apk_g" $?
        else
            missing "$apk_g" apk
        fi
    fi
    if [ -n "$fp_g" ]; then
        if [ -n "$FLATPAK" ]; then
            flatpak update -y --noninteractive -- $fp_p >"$T/out" 2>"$T/err" </dev/null
            results "$fp_g" $?
        else
            missing "$fp_g" flatpak
        fi
    fi
    if [ -n "$snap_g" ]; then
        if [ -n "$SNAP" ]; then
            snap refresh $snap_p >"$T/out" 2>"$T/err" </dev/null
            results "$snap_g" $?
        else
            missing "$snap_g" snap
        fi
    fi
    if [ -n "$pkg_g" ]; then
        if [ -n "$PKG" ]; then
            "$PKG" upgrade -y -- $pkg_p >"$T/out" 2>"$T/err" </dev/null
            results "$pkg_g" $?
        else
            missing "$pkg_g" pkg
        fi
    fi
    if [ -n "$swu_g" ]; then
        old_ifs=$IFS
        IFS='
'
        for g in $swu_g; do
            IFS=$old_ifs
            label=${g#*:}
            label=${label%%:*}
            if [ -z "$SWU" ]; then
                printf 'I\t%s\t127\tsoftwareupdate is not available\n' "$g"
                continue
            fi
            # no --restart: rebooting is left to the server policy
            softwareupdate -i "$label" >"$T/out" 2>"$T/err" </dev/null
            rc=$?
            if [ $rc -eq 0 ] && grep -qi restart "$T/out" "$T/err"; then
                MAC_RESTART=1
            fi
            printf 'I\t%s\t%s\t%s\n' "$g" "$rc" "$(if [ $rc -eq 0 ]; then echo ok; else lastmsg "$T/err" "$T/out"; fi)"
        done
        IFS=$old_ifs
    fi
    if [ -n "$bf_g$bc_g" ] && { [ -z "$BREW" ] || ! brew_ok brew; }; then
        missing "$bf_g $bc_g" brew
        bf_g= bc_g=
    fi
    if [ -n "$bf_g" ]; then
        brew_run 1200 upgrade --formula $bf_p >"$T/out" 2>"$T/err"
        results "$bf_g" $?
    fi
    if [ -n "$bc_g" ]; then
        brew_run 1200 upgrade --cask $bc_p >"$T/out" 2>"$T/err"
        results "$bc_g" $?
    fi
    set +f
}

# -------------------------------------------------------------------- remove

remove_result() {
    rr_source=$1
    rr_target=$2
    rr_rc=$3
    rr_message=$4
    if [ -z "$rr_message" ]; then
        if [ "$rr_rc" -eq 0 ]; then
            rr_message=ok
        else
            rr_message=$(lastmsg "$T/err" "$T/out")
            [ -n "$rr_message" ] || rr_message="command failed"
        fi
    fi
    printf 'I\t%s:%s\t%s\t%s\n' "$rr_source" "$rr_target" "$rr_rc" "$rr_message"
}

remove_dpkg() {
    if [ -z "$APT" ]; then
        remove_result dpkg "$1" 127 "apt-get is not available"
        return
    fi
    if ! apt-get -s remove -- "$1" >"$T/out" 2>"$T/err" </dev/null; then
        remove_result dpkg "$1" 1 ""
        return
    fi
    rd_count=$(awk '/^(Remv|Purg) / { n++ } END { print n + 0 }' "$T/out")
    if [ "$rd_count" -gt 1 ]; then
        rd_deps=$(awk -v name="$1" '
            BEGIN { split(name, n, ":") }
            /^(Remv|Purg) / && $2 != name && $2 != n[1] { printf "%s%s", sep, $2; sep = ", " }
            END { print "" }' "$T/out")
        remove_result dpkg "$1" 1 "refused: would also remove: $rd_deps"
        return
    fi
    apt-get -y -q -o DPkg::Lock::Timeout=120 remove -- "$1" >"$T/out" 2>"$T/err" </dev/null
    remove_result dpkg "$1" $? ""
}

remove_rpm() {
    if [ -z "$RPM" ]; then
        remove_result rpm "$1" 127 "rpm is not available"
        return
    fi
    if ! rpm -e --test -- "$1" >"$T/out" 2>"$T/err" </dev/null; then
        remove_result rpm "$1" 1 ""
        return
    fi
    if [ -n "$DNF" ]; then
        # keep now unused dependencies, only the named package goes
        "$DNF" -y --setopt=clean_requirements_on_remove=False remove "$1" >"$T/out" 2>"$T/err" </dev/null
        rp_rc=$?
    elif [ -n "$ZYPPER" ]; then
        zypper --non-interactive remove -- "$1" >"$T/out" 2>"$T/err" </dev/null
        rp_rc=$?
        # informational: 102 reboot needed, 103 restart zypper, 106 repos skipped
        case $rp_rc in 102 | 103 | 106) rp_rc=0 ;; esac
    else
        remove_result rpm "$1" 127 "dnf, yum or zypper is not available"
        return
    fi
    remove_result rpm "$1" "$rp_rc" ""
}

remove_apk() {
    if [ -z "$APK" ]; then
        remove_result apk "$1" 127 "apk is not available"
        return
    fi
    if ! apk info -r "$1" >"$T/out" 2>"$T/err" </dev/null; then
        remove_result apk "$1" 1 ""
        return
    fi
    ra_deps=$(awk '!/ is required by:$/ && NF { printf "%s%s", sep, $1; sep = ", " } END { print "" }' "$T/out")
    if [ -n "$ra_deps" ]; then
        remove_result apk "$1" 1 "refused: required by: $ra_deps"
        return
    fi
    apk del -- "$1" >"$T/out" 2>"$T/err" </dev/null
    ra_rc=$?
    if [ "$ra_rc" -eq 0 ] && apk info -e "$1" >/dev/null 2>&1; then
        ra_rc=1
        remove_result apk "$1" "$ra_rc" "package remains installed after removal"
        return
    fi
    remove_result apk "$1" "$ra_rc" ""
}

remove_pkg() {
    if [ -z "$PKG" ]; then
        remove_result pkg "$1" 127 "pkg is not available"
        return
    fi
    if ! "$PKG" delete -n -- "$1" >"$T/out" 2>"$T/err" </dev/null; then
        remove_result pkg "$1" 1 ""
        return
    fi
    # pkg delete also removes every package that depends on this one
    rk_deps=$(awk -v name="$1" '
        /^Installed packages to be REMOVED:/ { on = 1; next }
        on && /^\t/ { n = $1; sub(/:$/, "", n); if (n != name) { printf "%s%s", sep, n; sep = ", " }; next }
        on { on = 0 }
        END { print "" }' "$T/out")
    if [ -n "$rk_deps" ]; then
        remove_result pkg "$1" 1 "refused: would also remove: $rk_deps"
        return
    fi
    "$PKG" delete -y -- "$1" >"$T/out" 2>"$T/err" </dev/null
    remove_result pkg "$1" $? ""
}

remove_app() {
    if [ ! -d "$1" ] || [ -L "$1" ]; then
        remove_result app "$1" 1 "refused: application is missing, not a directory, or a symlink"
        return
    fi
    ra_bundle=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$1/Contents/Info.plist" 2>/dev/null | tr -d '\t\r\n' | cut -c 1-500)
    if [ -z "$ra_bundle" ]; then
        ra_bundle=$(defaults read "$1/Contents/Info" CFBundleIdentifier 2>/dev/null | tr -d '\t\r\n' | cut -c 1-500)
    fi
    case $ra_bundle in
    com.apple.*)
        remove_result app "$1" 1 "refused: Apple system application $ra_bundle"
        return
        ;;
    esac
    rm -rf -- "$1" >"$T/out" 2>"$T/err"
    ra_rc=$?
    if [ "$ra_rc" -eq 0 ] && { [ -e "$1" ] || [ -L "$1" ]; }; then
        ra_rc=1
        printf '%s\n' "application still exists after removal" >"$T/err"
    fi
    remove_result app "$1" "$ra_rc" ""
}

remove_target() {
    rt_source=$1
    rt_target=$2
    case $rt_source in
    dpkg) remove_dpkg "$rt_target" ;;
    rpm) remove_rpm "$rt_target" ;;
    pacman)
        if [ -n "$PACMAN" ]; then
            pacman -R --noconfirm -- "$rt_target" >"$T/out" 2>"$T/err" </dev/null
            remove_result pacman "$rt_target" $? ""
        else
            remove_result pacman "$rt_target" 127 "pacman is not available"
        fi
        ;;
    apk) remove_apk "$rt_target" ;;
    flatpak)
        if [ -n "$FLATPAK" ]; then
            flatpak uninstall -y --noninteractive "$rt_target" >"$T/out" 2>"$T/err" </dev/null
            remove_result flatpak "$rt_target" $? ""
        else
            remove_result flatpak "$rt_target" 127 "flatpak is not available"
        fi
        ;;
    snap)
        if [ -n "$SNAP" ]; then
            snap remove "$rt_target" >"$T/out" 2>"$T/err" </dev/null
            remove_result snap "$rt_target" $? ""
        else
            remove_result snap "$rt_target" 127 "snap is not available"
        fi
        ;;
    brew | brew-cask)
        if [ -z "$BREW" ] || ! brew_ok "$rt_source" >/dev/null; then
            remove_result "$rt_source" "$rt_target" 127 "brew is not available or has no safe owner"
        elif [ "$rt_source" = brew ]; then
            # stays below the remove script timeout so brew is stopped by brew_run
            brew_run 780 uninstall --formula "$rt_target" >"$T/out" 2>"$T/err"
            remove_result brew "$rt_target" $? ""
        else
            brew_run 780 uninstall --cask "$rt_target" >"$T/out" 2>"$T/err"
            remove_result brew-cask "$rt_target" $? ""
        fi
        ;;
    app) remove_app "$rt_target" ;;
    pkg) remove_pkg "$rt_target" ;;
    esac
}

# TrueNAS updates itself as a whole, its package database is only read
MANAGED="package updates are managed by TrueNAS"
truenas_main() {
    case $MODE in
    inventory | refresh)
        if has dpkg-query; then
            inv_dpkg
        else
            err dpkg-inventory "dpkg-query is not available"
        fi
        ;;
    scan) err apt "$MANAGED" ;;
    install)
        for g in "$@"; do
            printf 'I\t%s\t1\t%s\n' "$g" "$MANAGED"
        done
        ;;
    remove) printf 'I\t%s:%s\t1\t%s\n' "$1" "$2" "$MANAGED" ;;
    esac
}

main() {
    if is_truenas; then
        truenas_main "$@"
        return
    fi
    case $MODE in
    inventory) inventory ;;
    scan)
        scan
        reboot_line
        ;;
    refresh)
        inventory
        scan
        reboot_line
        ;;
    install)
        install_guids "$@"
        reboot_line
        ;;
    remove) remove_target "$@" ;;
    esac
}

MAC_RESTART=
# cap line length, except inside the JSON block which must stay parseable
main "$@" | awk '
    $0 == "J\tBEGIN" || $0 == "A\tBEGIN" { j = 1 }
    $0 == "J\tEND" || $0 == "A\tEND" { j = 0 }
    { print j ? $0 : substr($0, 1, 8000) }'
exit 0
