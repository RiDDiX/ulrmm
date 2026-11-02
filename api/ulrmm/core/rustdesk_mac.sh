#!/bin/bash
# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

# macOS version of rustdesk_linux.sh. Same placeholders, one result line.
#
# The launchd plists are what the RustDesk installer writes
# (src/platform/privileges_scripts). That installer asks for an admin
# password, which this script cannot answer. Screen Recording and
# Accessibility have to be allowed on the Mac, or the session is black
# and takes no input.

export PATH=/usr/bin:/bin:/usr/sbin:/sbin
log=/Library/Logs/rustdesk-deploy.log
dir=$(mktemp -d /tmp/rustdesk-deploy.XXXXXX) || exit 1

(
    fail() {
        echo "failed: $*"
        msg=$*
        # a failed upgrade puts the previous bundle back
        if [ -d "$old" ]; then
            stop
            { rm -rf "$app" && mv "$old" "$app"; } && msg="$msg; RustDesk $have was put back"
            start
        fi
        echo "RUSTDESK_FAIL $msg" >"$dir/result"
        exit 1
    }
    signed() {
        codesign --verify --deep --strict "$1" &&
            codesign -dv "$1" 2>&1 | grep -qx 'TeamIdentifier=HZF9JMC8YN'
    }
    plist() { /usr/libexec/PlistBuddy -c "Print :$2" "$1/Contents/Info.plist"; }
    older() { [ "$1" != "$2" ] && [ "$(printf '%s\n' "$1" "$2" | sort -V | head -n 1)" = "$1" ]; }
    # hash of the ID, key pair and password entries (key_pair spans several
    # lines); it is only compared, never logged
    fingerprint() {
        lines=$(awk '/^[A-Za-z_]+ = /{k=/^(enc_id|password|salt|key_pair) = /} /^\[[A-Za-z_]/{k=0} k' "$toml") &&
            [ -n "$lines" ] && printf '%s\n' "$lines" | shasum -a 256
    }
    # the order of RustDesk's own update script. launchd would otherwise
    # restart the service from a half-swapped bundle.
    stop() {
        [ "$uid" = 0 ] || launchctl bootout "gui/$uid/com.carriez.RustDesk_server"
        launchctl unload "$daemon"
        pkill -f '^/Applications/RustDesk\.app/Contents/MacOS/'
    }
    start() {
        launchctl load -w "$daemon"
        [ "$uid" = 0 ] || launchctl bootstrap "gui/$uid" "$agent"
    }
    echo "=== $(date)"
    mode='rdMode'
    [ "$mode" = update ] || [ -n "${RD_PASSWORD:-}" ] || fail "no password was handed to the script"
    app=/Applications/RustDesk.app
    new=$dir/RustDesk.app
    old=$dir/old.app
    rd=$app/Contents/MacOS/RustDesk
    daemon=/Library/LaunchDaemons/com.carriez.RustDesk_service.plist
    agent=/Library/LaunchAgents/com.carriez.RustDesk_server.plist
    toml=/var/root/Library/Preferences/com.carriez.RustDesk/RustDesk.toml
    uid=$(stat -f %u /dev/console)

    # from the plist: the bundle may still be the user's, so root does not run it yet
    have=
    if [ -x "$rd" ]; then
        have=$(plist "$app" CFBundleShortVersionString)
        printf '%s' "$have" | grep -Eqx '[0-9]+(\.[0-9]+){1,3}' || fail "cannot read the installed RustDesk version"
    fi
    if [ "$mode" = update ]; then
        [ -n "$have" ] || fail "RustDesk is not installed, use Install or reconfigure"
        older 'rdVersion' "$have" && fail "not downgrading: RustDesk rdVersion is older than the installed $have"
        before=$(fingerprint) || fail "the RustDesk config holds no ID or password"
    fi

    want=$have
    # only an update upgrades, so a reconfigure can always rotate the password
    if [ -z "$have" ] || { [ "$mode" = update ] && older "$have" 'rdVersion'; }; then
        # the swap stops every RustDesk process. Arguments are matched, never logged.
        # At the login window there is no --cm, only the session's TCP
        # connection: to hbbr (21117) or the viewer. 21114-21116 belong to the
        # ID server.
        if [ -n "$have" ]; then
            pgrep -f 'MacOS/RustDesk (--cm|--connect|--play|--file-transfer|--view-camera|--port-forward|--terminal|--whiteboard|--rdp|rustdesk:)' >/dev/null &&
                fail "busy: a RustDesk session is open on this device"
            if pids=$(pgrep -d , -f '^/Applications/RustDesk\.app/Contents/MacOS/'); then
                conns=$(lsof -w -nP -a -p "$pids" -iTCP -sTCP:ESTABLISHED -Fn 2>"$dir/lsof.err")
                rc=$?
                # lsof also exits 1 when a process has no such connection
                { [ "$rc" -le 1 ] && [ ! -s "$dir/lsof.err" ]; } ||
                    fail "busy: cannot list the TCP connections"
                printf '%s\n' "$conns" | grep '^n' | grep -Evq ':2111[456]$' &&
                    fail "busy: a RustDesk session is open on this device"
            fi
        fi
        want='rdVersion'
        curl -fsSL --max-time 180 -o "$dir/rustdesk.dmg" 'rdDmgUrl' || fail "download failed: rdDmgUrl"
        [ "$(shasum -a 256 "$dir/rustdesk.dmg" | awk '{print $1}')" = 'rdDmgSha256' ] ||
            fail "checksum mismatch: rdDmgUrl"
        mkdir "$dir/mnt"
        hdiutil attach -nobrowse -readonly -mountpoint "$dir/mnt" "$dir/rustdesk.dmg" ||
            fail "the disk image does not mount"
        ditto --noacl "$dir/mnt/RustDesk.app" "$new"
        rc=$?
        hdiutil detach "$dir/mnt"
        [ "$rc" = 0 ] || fail "copying RustDesk.app failed"
    elif [ -n "$(find "$app" \( ! -user root -o ! -type l -perm +022 \) -print -quit)" ]; then
        # upstream gives the bundle to the user, who may have changed any file
        # in it or still hold one open, so only a fresh copy is checked and used
        ditto --noacl "$app" "$new" || fail "copying RustDesk.app failed"
    fi
    # the LaunchDaemon runs the bundle's service binary as root, so the bundle
    # must be root's and signed by RustDesk's team (the Screen Recording and
    # Accessibility grants are tied to that Team ID as well)
    if [ -e "$new" ]; then
        { chown -Rh root:wheel "$new" && chmod -R go-w "$new"; } ||
            fail "RustDesk.app could not be made root-owned"
        signed "$new" || fail "RustDesk.app failed the signature check"
        # the seal covers Info.plist, so these values are RustDesk's
        [ "$(plist "$new" CFBundleIdentifier) $(plist "$new" CFBundleShortVersionString)" = "com.carriez.rustdesk $want" ] ||
            fail "RustDesk.app is not com.carriez.rustdesk $want"
        if [ -n "$have" ] && [ "$want" != "$have" ]; then
            stop
            mv "$app" "$old" || { start; fail "copying RustDesk.app failed"; }
            mv "$new" "$app" || fail "copying RustDesk.app failed"
            start
        else
            { rm -rf "$app" && mv "$new" "$app"; } || fail "copying RustDesk.app failed"
        fi
    else
        signed "$app" || fail "RustDesk.app failed the signature check"
    fi

    if [ ! -f "$daemon" ]; then
        cat >"$daemon" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.carriez.RustDesk_service</string>
    <key>AssociatedBundleIdentifiers</key>
    <string>com.carriez.rustdesk</string>
    <key>KeepAlive</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>1</integer>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/sh</string>
        <string>-c</string>
        <string>/Applications/RustDesk.app/Contents/MacOS/service</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>WorkingDirectory</key>
    <string>/Applications/RustDesk.app/Contents/MacOS/</string>
    <key>StandardErrorPath</key>
    <string>/tmp/rustdesk_service.err</string>
    <key>StandardOutPath</key>
    <string>/tmp/rustdesk_service.out</string>
</dict>
</plist>
EOF
        if ! { chown root:wheel "$daemon" && chmod 644 "$daemon" && launchctl load -w "$daemon"; }; then
            fail "the RustDesk service does not start"
        fi
    fi

    if [ ! -f "$agent" ]; then
        cat >"$agent" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.carriez.RustDesk_server</string>
    <key>AssociatedBundleIdentifiers</key>
    <string>com.carriez.rustdesk</string>
    <key>LimitLoadToSessionType</key>
    <array>
        <string>LoginWindow</string>
        <string>Aqua</string>
    </array>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
        <key>AfterInitialDemand</key>
        <false/>
    </dict>
    <key>ThrottleInterval</key>
    <integer>1</integer>
    <key>RunAtLoad</key>
    <true/>
    <key>ProgramArguments</key>
    <array>
        <string>/Applications/RustDesk.app/Contents/MacOS/RustDesk</string>
        <string>--server</string>
    </array>
    <key>WorkingDirectory</key>
    <string>/Applications/RustDesk.app/Contents/MacOS/</string>
    <key>ProcessType</key>
    <string>Interactive</string>
</dict>
</plist>
EOF
        if ! { chown root:wheel "$agent" && chmod 644 "$agent"; }; then
            fail "could not write $agent"
        fi
        # launchd starts it at the next login; a user already logged in gets it now
        [ "$uid" != 0 ] && launchctl bootstrap "gui/$uid" "$agent"
    fi

    if [ "$mode" = update ]; then
        # an update never sets the password
        for i in $(seq 30); do
            launchctl print system/com.carriez.RustDesk_service | grep -q 'state = running' && break
            [ "$i" = 30 ] && fail "the RustDesk service does not start"
            sleep 1
        done
    else
        # root's CLI talks to the RustDesk process of the logged in user
        for i in $(seq 30); do
            "$rd" --password "$RD_PASSWORD" | grep -qx 'Done!' && break
            [ "$i" = 30 ] && fail "the RustDesk service did not take the password (is a user logged in?)"
            sleep 2
        done
    fi
    srvlog="/Users/$(stat -f %Su /dev/console)/Library/Logs/RustDesk/server/RustDesk_rCURRENT.log"
    seen=$(stat -f %z "$srvlog" 2>/dev/null || echo 0)
    "$rd" --config 'rdConfig'
    [ "$("$rd" --option custom-rendezvous-server | tail -n 1)" = 'rdHost' ] ||
        fail "the server settings did not stick"
    id=$("$rd" --get-id | tail -n 1)
    [ -n "$id" ] || fail "RustDesk --get-id printed nothing"
    # Local Network has to be allowed, or the client cannot reach hbbs and
    # the ID never registers. The client retries about every 17 s.
    for i in $(seq 20); do
        tail -c +$((seen + 1)) "$srvlog" 2>/dev/null | grep -q 'No route to host' &&
            fail "RustDesk on this Mac cannot reach rdHost (No route to host). Allow RustDesk under System Settings > Privacy & Security > Local Network, then deploy again"
        sleep 1
    done
    ver=$("$rd" --version | head -n 1)
    if [ "$mode" = update ]; then
        [ "$id" = 'rdExpectId' ] || fail "the RustDesk ID changed to $id, use Install or reconfigure"
        [ "$ver" = 'rdVersion' ] || fail "the update left RustDesk at $ver instead of rdVersion"
        [ "$(fingerprint)" = "$before" ] ||
            fail "the RustDesk key or password changed during the update, use Install or reconfigure"
    fi
    echo "RUSTDESK_OK $id $ver" >"$dir/result"
) </dev/null >>"$log" 2>&1

cat "$dir/result" 2>/dev/null
rm -rf "$dir"
