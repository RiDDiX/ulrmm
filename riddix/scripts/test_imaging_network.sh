#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

# Exercise recovery's TLS upload across a real tunnel and an available fallback.
# Requires Linux root, iproute2, WireGuard tools, util-linux and OpenSSL.
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
if [[ ${1:-} != --isolated ]]; then
    exec unshare --net -- "$script_dir/$(basename -- "$0")" --isolated
fi
if [[ $(readlink /proc/self/ns/net) == $(readlink /proc/1/ns/net) ]]; then
    echo "Run the test inside an isolated network namespace." >&2
    exit 1
fi
umask 077
workdir=$(mktemp -d)
cleanup() {
    if [[ -n ${http_pid:-} ]]; then kill "$http_pid" 2>/dev/null || true; fi
    if [[ -n ${server_pid:-} ]]; then kill "$server_pid" 2>/dev/null || true; fi
    cd /
    rm -rf -- "$workdir"
}
trap cleanup EXIT
cd "$workdir"
wg=$(command -v wg)
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=imaging-test \
    -addext subjectAltName=IP:10.77.0.2 -keyout key.pem -out cert.pem 2>/dev/null
"$wg" genkey > client.key
"$wg" genkey > server.key
clientpub=$("$wg" pubkey < client.key)
serverpub=$("$wg" pubkey < server.key)

unshare -n sleep infinity &
server_pid=$!
while [[ "$(readlink /proc/"$server_pid"/ns/net)" == "$(readlink /proc/self/ns/net)" ]]; do sleep .05; done
ip link add underlay type veth peer name peerlink netns "$server_pid"
ip addr add 10.70.0.1/24 dev underlay
ip link set underlay up
nsenter -t "$server_pid" -n ip addr add 10.70.0.2/24 dev peerlink
nsenter -t "$server_pid" -n ip link set peerlink up
ip link add wg0 type wireguard
nsenter -t "$server_pid" -n ip link add wg0 type wireguard
ip addr add 10.77.0.1/32 dev wg0
nsenter -t "$server_pid" -n ip addr add 10.77.0.2/32 dev wg0
"$wg" set wg0 private-key client.key peer "$serverpub" allowed-ips 10.77.0.2/32 endpoint 10.70.0.2:51820
nsenter -t "$server_pid" -n "$wg" set wg0 private-key server.key listen-port 51820 peer "$clientpub" allowed-ips 10.77.0.1/32
ip link set wg0 up
nsenter -t "$server_pid" -n ip link set wg0 up
ip route add 10.77.0.2/32 dev wg0 metric 10
ip route add 10.77.0.2/32 via 10.70.0.2 dev underlay metric 500
nsenter -t "$server_pid" -n ip route add 10.77.0.1/32 dev wg0
nsenter -t "$server_pid" -n python3 - > requests.log 2> http.log <<'PY_SERVER' &
import http.server
import ssl

class Handler(http.server.BaseHTTPRequestHandler):
    def do_PUT(self):
        payload = self.rfile.read(int(self.headers["Content-Length"]))
        print(self.client_address[0], payload, flush=True)
        self.send_response(204)
        self.end_headers()

server = http.server.HTTPServer(("", 4443), Handler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("cert.pem", "key.pem")
server.socket = ctx.wrap_socket(server.socket, server_side=True)
server.serve_forever()
PY_SERVER
http_pid=$!
for _ in {1..100}; do
    nsenter -t "$server_pid" -n ss -lnt | grep -q ':4443 ' && break
    sleep .05
done
PYTHONPATH="$script_dir" python3 - <<'PY'
import subprocess
from unittest import mock
from ulrmm_image_recovery import Transfer, RecoveryError

url = "https://10.77.0.2:4443/imaging/transfers/00000000-0000-4000-8000-000000000001/"
internal = Transfer(url, "temporary-test-token-value", "wg0", "cert.pem")
internal.request("PUT", "data/?offset=0", b"through-tunnel")
subprocess.run(["ip", "route", "del", "10.77.0.2/32", "dev", "wg0", "metric", "10"], check=True)
subprocess.run(["wg", "set", "wg0", "peer", subprocess.check_output(["wg", "show", "wg0", "peers"], text=True).strip(), "remove"], check=True)
opener = internal.opener.open
try:
    with mock.patch("ulrmm_image_recovery.time.sleep"), mock.patch.object(internal.opener, "open", side_effect=lambda request, timeout: opener(request, timeout=1)):
        internal.request("PUT", "data/?offset=14", b"must-not-arrive")
except RecoveryError as exc:
    print(exc)
else:
    raise AssertionError("Internal transfer succeeded after route moved to underlay")
internet = Transfer(url, "temporary-test-token-value", ca_file="cert.pem")
internet.request("PUT", "data/?offset=14", b"allowed-direct")
PY
cat requests.log
test "$(wc -l < requests.log)" = 2
grep -Fqx "10.77.0.1 b'through-tunnel'" requests.log
grep -Fqx "10.70.0.1 b'allowed-direct'" requests.log
