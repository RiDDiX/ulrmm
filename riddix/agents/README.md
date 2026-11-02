# Agent builds

The server builds its own agents from the agent repo and publishes them
under `/agentdist/`. Installed agents fetch binaries, Windows installers,
Python zips and the Chocolatey install script from this directory, not from
third-party hosts. The build itself downloads pinned, sha256-checked tools
at build time (Go, rcodesign, Inno Setup, the Chocolatey script) and mirrors
the Python zips from `ULRMM_PY_ZIP_URL`. The entry point is
`build_agents.sh`; it sources `sign.sh` and runs `write_brand.py`.

## The /agentdist/ contract

`install.sh` and `restore.sh` write this nginx location (`rmm_nginx_conf` in
`riddix/scripts/install_lib.sh`, `AGENT_ROOT` is `/opt/ulrmm-agents`):

```nginx
location /agentdist/ {
    alias /opt/ulrmm-agents/dist/;
    default_type application/octet-stream;
}
```

The file names in `dist/` are the contract:

| File | Content |
|---|---|
| `<AGENT_ARTIFACT_NAME>-v<LATEST_AGENT_VER>-<os>-<arch>` | agent binary; Windows adds `.exe` and is the installer |
| `<name>-windows-<arch>.exe.agent.sha256` | sha256 of the program inside the Windows installer |
| `enroll-pubkey.txt` | public key the build carries for enrollment tokens |
| `python/py<version>_<arch>.zip` | embedded Python for Windows agents |
| `chocolatey-install.ps1` | Chocolatey install script from `ULRMM_CHOCO_URL`, sha256 pinned with `ULRMM_CHOCO_SHA256`; the server hands URL and hash to Windows agents, without the file they load it unchecked from chocolatey.org |

`api/ulrmm/agents/utils.py` derives every download URL as
`{get_agents_dist_url()}/{agent_artifact(ver, plat, goarch)}`.
`get_agents_dist_url()` returns `SELF_BUILT_AGENTS_URL` if set, otherwise
`<backend url>/agentdist`; `agent_artifact()` in
`api/ulrmm/ulrmm/agent_ident.py` builds the name from `AGENT_ARTIFACT_NAME`.
Set `SELF_BUILT_AGENTS_URL` in `local_settings.py` only when the files are
served from somewhere else. `GET /api/v3/<agent_id>/selfheal/` hashes the
same files from `AGENTS_DIST_DIR` (default `/opt/ulrmm-agents/dist`) and
answers 404 when the file is not there.

## Running a build

`install.sh` and `restore.sh` run `build_agents_step` once at the end,
`update.sh` runs it on every run. `--skip-agent-build` keeps the existing
files. Manual call, as the install user, without sudo:

```bash
bash /rmm/riddix/agents/build_agents.sh
```

Settings: environment first, then `local_settings.py`, then `settings.py`:

| Variable | Default |
|---|---|
| `AGENT_VER` | `LATEST_AGENT_VER` from the settings |
| `ULRMM_AGENT_ROOT` | `/opt/ulrmm-agents` (holds `src`, `dist`, `go`, `wine`, `tools`) |
| `ULRMM_API_DIR` | `/rmm/api/ulrmm` |
| `ULRMM_AGENT_GIT_URL` | `ULRMM_GIT_URL` with `ulrmm-agent.git` as the last path part |
| `ULRMM_AGENT_GIT_REF` | `main` (branch or tag) |
| `ULRMM_PY_ZIP_URL` | `<ULRMM_AGENT_GIT_URL without .git>/releases/download/python` |

A private agent repo is fetched with `ULRMM_GIT_TOKEN` and `ULRMM_GIT_USER`
through `GIT_ASKPASS`; the token is not in argv, the URL or `.git/config`
and only goes to the host of `ULRMM_GIT_URL`. The Go toolchain comes from
`riddix/scripts/go_toolchain.sh` (`GO_VER`, sha256 checked), installed under
`$ULRMM_AGENT_ROOT/go` and shared with the nats-api build.

The script stops rather than publishing a partial build:

- Only one run at a time: `flock` on `$ULRMM_AGENT_ROOT/.build.lock`.
- `AGENT_VER` must be `X.DD.MM.YYYY` with a valid date and must equal
  `version` in `main.go` of the checked-out ref. The built Linux binary is
  run with `-version` and compared with the file name.
- After `write_brand.py`, `IdentArtifact` in `agent/brand.go` must equal
  `AGENT_ARTIFACT_NAME`.
- Targets: `linux/amd64 linux/386 linux/arm64 linux/arm darwin/amd64
  darwin/arm64 freebsd/amd64 freebsd/arm64`, plus `windows/amd64` and
  `windows/386` when `iscc` is available.
- Every artifact of this run must exist before anything is copied to
  `$DIST`. Each file goes through a unique staging name and `mv`, so a
  download never sees a half-written file.

## Windows installers

The installer is built from `build/setup.iss` of the agent repo with `iscc`
on the PATH. The program inside is built as `agent.exe`, signed if signing
is set up, then packed; the installer itself is signed afterwards.
`goversioninfo` v1.4.1 writes the version resource and the
`requireAdministrator` manifest; if it cannot be installed the build stops.

`install-innosetup.sh` runs on Debian x86_64 only (wine32), as the build
user, with sudo for apt. It installs Wine (i386), `xvfb` and `xauth`,
creates a win32 prefix under `$ULRMM_AGENT_ROOT/wine`, installs Inno Setup
`INNO_VER` (6.4.3, sha256 pinned, from the jrsoftware GitHub releases) and
writes `/usr/local/bin/iscc`, a wrapper that runs under `xvfb-run`.
`build_agents_step` calls it when `iscc` is missing and the host is x86_64.
Without `iscc`, `build_agents.sh` prints a warning and builds only Linux,
macOS and FreeBSD, exit code 0; Windows endpoints get no update from this
server until a run with `iscc` succeeds.

## Python for Windows agents

Windows agents download `py<version>_<arch>.zip` from `BrandPyURL` and
accept it only if the sha256 matches the table in `agent/pyzip.go` of the
agent repo. `build_agents.sh` mirrors the zips listed in that table from
`ULRMM_PY_ZIP_URL` to `$DIST/python` and checks them against the same
table. A missing or mismatching zip is a warning, not an error; the Python
installation on the Windows agent fails later instead.

`BrandPyURL` is `ULRMM_AGENT_PY_URL` if set, otherwise
`<agents dist url>/python`. Like `BrandPubIPURL` (`ULRMM_AGENT_PUBIP_URL`,
set by `install.sh` to `https://<backend>/pubip`) it is compiled in, so a
change means rebuild and rollout.

## Enrollment key and identity

`write_brand.py` writes the public key of `ENROLL_SIGNING_KEY` (Ed25519,
base64) as `BrandEnrollPubKey` into `agent/brand.go`; the agent verifies
the signed enrollment data of deployment installers with it. After the
publish, `build_agents.sh` writes the same value to `$DIST/enroll-pubkey.txt`.
The server hands out installers only while this file matches the current
key (`dist_pubkey_ok` in `api/ulrmm/deploy/signing.py`), otherwise the
deploy endpoints answer 503 "agent build needed: run update.sh".
`install.sh`, `update.sh` and `restore.sh` create the key once
(`ensure_enroll_key` in `install_lib.sh`). A new key means rebuild, and
every installer handed out before is invalid.

The `AGENT_*` settings in `api/ulrmm/ulrmm/settings.py` (service name,
paths, registry key, task prefix, `AGENT_ARTIFACT_NAME`, `AGENT_INNO_APPID`)
are the agent identity. `write_brand.py` bakes them into `brand.go` and
`brand.env`. Do not change them on a server with installed agents: an agent
that reports another identity gets no artifacts (`agent_ident_for`), and a
different Inno `AppId` installs a second copy next to the old one. Only
display texts come from the branding (`product_name`, `company_name`,
`support_url`, `favicon` or `logo` as icon).

## Self-healing

The agent service keeps a verified copy of its binary with sha256 under
`<data dir>/selfheal/` and registers a scheduled job that runs
`<copy> -m selfheal`: a systemd timer on Linux, a LaunchDaemon
`<plist label>.selfheal` on macOS, `/etc/cron.d/<service>-selfheal` on
FreeBSD (every 15 minutes), a scheduled task as SYSTEM on Windows. On
TrueNAS SCALE a POSTINIT entry (`midclt`) restores the units after an update.

The job checks the binary sha256, the service registration and state, and
the heartbeat of the main loop (older than 30 minutes counts as stuck). It
repairs by restart, by restoring the local copy or by installing the build
the server names in `GET /api/v3/<agent_id>/selfheal/` (with the signed
update document). At most 3 repairs per 24 hours; each is reported with
`POST` to the same endpoint and lands in the server debug log. Without
agent config the job removes itself, so an uninstalled agent never comes
back. Per device off switch: `selfheal.disabled` in the data directory.

## Signing

Off until configured. Values come from the environment or
`local_settings.py`; passwords only as files, never on the command line.

| Setting | Content |
|---|---|
| `ULRMM_SIGN_WIN_PFX` | PKCS#12 with Authenticode certificate and key |
| `ULRMM_SIGN_WIN_PASS_FILE` | file holding only the PFX password |
| `ULRMM_SIGN_MAC_P12` | PKCS#12, Developer ID Application or own certificate |
| `ULRMM_SIGN_MAC_PASS_FILE` | file holding only the P12 password |
| `ULRMM_NOTARY_API_KEY_FILE` | optional, JSON from `rcodesign encode-app-store-connect-api-key` |
| `ULRMM_SIGN_TIMESTAMP_URL` | optional, RFC 3161 timestamp service (outbound connection at build time) |

Windows: `osslsigncode` must be installed (`apt install osslsigncode`).
`sign_win` signs with sha256 and checks that a signature is present before
replacing the file: first `agent.exe` inside the installer, then the installer.

macOS: `rcodesign` `RCODESIGN_VER` (0.29.0) is downloaded with a pinned
sha256 to `$ULRMM_AGENT_ROOT/tools`. `sign_mac` signs with
`--binary-identifier <AGENT_ARTIFACT_NAME>` and the hardened runtime flag,
then verifies. TCC approvals such as Full Disk Access are tied to identifier
and certificate and survive agent updates; an ad-hoc signature is tied to
the cdhash and is lost on every build. rcodesign reads only legacy PKCS#12
files: export with `openssl pkcs12 -export -legacy`. With
`ULRMM_NOTARY_API_KEY_FILE` set, each binary is zipped and submitted with
`rcodesign notary-submit --wait`; a bare binary cannot be stapled.
