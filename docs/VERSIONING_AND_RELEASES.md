# Versioning and Releases

UniversalLocal RMM · 2026-10-28 · server and web at `2.27.10.2026`, agent at `1.27.10.2026`

Before this document there were three product versions in three files and no
check that they agreed. This defines one canonical
source and one version format, says who reads it, and records why the agent
keeps a version of its own.

## Canonical source

`VERSION` in the root of the server repository. One line in the format of the
[version scheme](#version-scheme), without a `v`:

```
1.24.09.2026
```

That file is the product version of UniversalLocal RMM. Nothing else in the
repositories may spell a product version out a second time.
`riddix/scripts/check_versions.py` enforces that for what it can see: the
`ULRMM_VERSION` assignments in `settings.py`, the web `package.json` and the two
agent files. It cannot see a runtime override — `settings.py` star-imports
`sso/settings.py` and `local_settings.py` *after* `ULRMM_VERSION` is set,
and `update.sh` writes `local_settings.py`, so a `ULRMM_VERSION` line placed there
would win with a green gate. Do not put one there.

`settings.py` exposes the value as `ULRMM_VERSION`, the name the call sites, the
OpenAPI schema and the dashboard read:

```python
VERSION_FILE = BASE_DIR.parent.parent / "VERSION"
if not VERSION_FILE.is_file():
    raise ImproperlyConfigured(...)
ULRMM_VERSION = VERSION_FILE.read_text().strip()
```

On the server that is `/rmm/VERSION`, in CI the repository root. A missing file
raises `ImproperlyConfigured` with the path in the message — the server refuses
to start rather than report a version it invented.

## How each consumer reads it

File references name a file and, where it helps, a symbol. No line numbers:
nothing regenerates them and they are wrong after the next edit.

| Consumer | Reads | File |
|---|---|---|
| Django (all of it) | `settings.ULRMM_VERSION`, loaded from `VERSION` at import | `api/ulrmm/ulrmm/settings.py` (`VERSION_FILE`) |
| `manage.py get_config version` | `settings.ULRMM_VERSION` | `core/management/commands/get_config.py` |
| OpenAPI schema | `SPECTACULAR_SETTINGS["VERSION"]` | `settings.py` |
| Dashboard | `dashboard_info()["version"]`, `["latest_version"]` | `core/views.py` (`dashboard_info`) |
| `/core/status/`, `/core/status/v2/` | `settings.ULRMM_VERSION` | `core/views.py` (`status`, `status_v2`) |
| `update.sh`, target version | `git -C /rmm show "<ref>:VERSION"` | `update.sh` (`LATEST_ULRMM_VER`) |
| `update.sh`, installed version | `/rmm/VERSION` | `update.sh` (`CURRENT_ULRMM_VER`) |
| `install.sh`, `restore.sh` | `VERSION` of the target branch, read in the preflight before the host changes | `riddix/scripts/install_lib.sh` (`repo_preflight`) |
| nats-api | `-X main.version=<VERSION>` at build time, printed by `nats-api -version` | `riddix/scripts/build_natsapi.sh` |
| Gate check | `VERSION` plus an AST parse of `settings.py` | `riddix/scripts/check_versions.py` |
| Web gate | `VERSION` of the server tree, passed as an argument | `ulrmm-web/scripts/check-version.mjs` |

`update.sh` has no fallback for either read. Every host on this layout has
`/rmm/VERSION`; a target ref without the file aborts the run before anything
changes.

### Not the product version

| Value | What it actually names | Left alone because |
|---|---|---|
| `APP_VER = "0.0.203"` | cache-busting nudge for open browser tabs (`/core/version/`) | Deliberately unrelated to a release: it is bumped when the SPA bundle changes, which is not the same event as a product release. |
| `LATEST_AGENT_VER = "1.27.10.2026"` | the agent version | See [Agent](#agent-version-line). |
| `SCRIPT_VERSION` in `update.sh`, `install.sh`, `backup.sh`, `restore.sh` | self-update counter for that one script | Monotonic integer, not a version. Must be bumped whenever the script changes, or installed copies never replace themselves. |
| `MESH_VER`, `NATS_SERVER_VER`, `INSTALL_NUSHELL_VERSION`, `INSTALL_DENO_VERSION` | third-party releases we download | Pinned to what those projects publish. A new `NATS_SERVER_VER` also needs `NATS_PINNED_VER` and both `NATS_SHA256_*` sums in `riddix/scripts/install_lib.sh` (from the release `SHA256SUMS`); without them install, restore and update stop at the nats-server step. |
| `PYTHON_VER`, `PYTHON_SHA256` in `riddix/scripts/install_lib.sh` | the CPython release built on the host | A bump changes both, the sum of the python.org source tarball. |

## Exposure

Where a version is visible to a user or an operator, and whether it is the
product version.

Same rule about line numbers as above.

| Surface | Shows | Status | File |
|---|---|---|---|
| WebUI navigation rail | `v<server version>` under the product name | done | `ulrmm-web/src/layouts/MainLayout.vue` (nav rail) |
| WebUI header | `v<server version>` next to the logo | done | `ulrmm-web/src/layouts/MainLayout.vue` (header) |
| WebUI update chip | `v<remote version>+<sha> available` | done | `ulrmm-web/src/layouts/MainLayout.vue` (update chip) |
| WebUI "about" / help menu | nothing — there is no about dialog, the header carries the version | done | `MainLayout.vue` (FileBar has support and issue links only) |
| Web SPA own version | not displayed anywhere | done (deliberate) | `ulrmm-web/package.json` |
| `GET /core/dashinfo/` | `version`, `latest_version` | done | `core/views.py` (`dashboard_info`) |
| `GET /core/status/`, `/core/status/v2/` | `version`, `latest_agent_version` | done | `core/views.py` (`status`, `status_v2`) |
| OpenAPI schema (`/api/schema/`) | `info.version` | done | `settings.py` (`SPECTACULAR_SETTINGS`) |
| `manage.py get_config version` | product version | done | `core/management/commands/get_config.py` |
| `nats-api -version` | product version, then Go build info | done | `main.go`, `riddix/scripts/build_natsapi.sh` |
| `GET /core/version/` | `APP_VER`, not the product version | done (deliberate) | `core/views.py` (`get_core_version`) |
| Agent enrolment (`POST /api/v3/newagent/`) | no version field is sent | pending | `ulrmm-agent/agent/install.go` (`NewAgentPayload`) |
| Agent installer self-check | agent version vs `LATEST_AGENT_VER` | agent line | `apiv3/views.py` (`CheckIn.post`), `ulrmm-agent/agent/install.go` |
| Agent heartbeat (`agent-hello` over NATS) | agent version, written straight to `Agent.version` | agent line | `ulrmm-agent/agent/checkin.go`, `natsapi/svc.go` |
| Agent inventory (agent table, summary tab, fleet overview) | `Agent.version` | agent line | `ulrmm-web/src/components/AgentTable.vue` |
| Agent `--version` | agent version plus Go build info | agent line | `ulrmm-agent/agent/utils.go` |
| Agent logs | agent version on startup | agent line | `ulrmm-agent/agent/utils.go` |
| Windows installer and file metadata | numeric `YYYY.M.D.X` (`VersionInfoVersion`, file version), `v<agent version>` as text and as `AppVersion` | agent line | `ulrmm-agent/build/setup.iss`, `versioninfo.json`, `riddix/agents/build_agents.sh` |
| Release artifacts (`ulrmm-agent-v<x>-<os>-<arch>`) | agent version | agent line | `riddix/agents/build_agents.sh` |
| Server release artifacts | signed assets per `v<version>` tag; git deployment stays possible | done | `.github/workflows/release.yml`, `riddix/scripts/release_build.sh`, `update.sh` |

"agent line": those surfaces are correct, they show the agent version, not the
product version. The reason is below.

## Release procedure

Releases are published as signed assets by `.github/workflows/release.yml`,
which runs on a pushed `v*` tag and calls `riddix/scripts/release_build.sh` to
build and sign them. Deploying the server from git remains possible. Every repository keeps
a `CHANGELOG.md` (`## <version> (<date>)` headings, `- ` items; the script
library uses `## <date>`). The dashboard's About panel shows all four.

1. Set `VERSION` in the server repository to what
   `python3 riddix/scripts/check_versions.py --next` prints. That is the whole
   version bump.
2. Set the same string in `ulrmm-web/package.json` and the two root `version`
   fields of `ulrmm-web/package-lock.json`.
3. Bump `SCRIPT_VERSION` in every script that changed (`update.sh`, `install.sh`,
   `restore.sh`, `backup.sh`), otherwise deployed copies keep running the old one.
4. Add the release to `CHANGELOG.md` in every repository that changed, with the
   new version and date. A component that only follows the version gets the
   line "No changes here; version kept in step with the other components".
5. Run the gates (below). `check_versions.py` must be green before a commit.
6. Commit both repositories, tag both `v<version>`, push to GitHub (branch `main`).
   The pushed tag triggers `release.yml`, which builds and signs the assets.
7. On the VM, as the install user: `/rmm/update.sh`. It self-updates, reads the
   target `VERSION` from the fetched ref, warns if the fetched web tree
   disagrees, builds the SPA and nats-api from source, migrates, restarts.
8. Agents: only when the agent changed. Take the version from
   `check_versions.py --next agent` and set it as `LATEST_AGENT_VER` in
   `settings.py` and in the agent's `main.go` and `build/setup.iss`
   (`MyAppVersion`), then tag the agent repository `v<version>`. `update.sh`
   runs `riddix/agents/build_agents.sh` itself; the hourly `update_agents`
   command then rolls the fleet forward.

`post_update_tasks` (run by `update.sh` after the migrations) deletes
`ULRMM_LATEST_VER_CACHE_KEY`. Without that, the remote version read before the
update stays cached for 1800s and the dashboard advertises the release that was
just installed as still available, for up to half an hour after every deploy. The
only other thing that clears that key is the manual "clear cache" button
(`core/utils.py`, `clear_entire_cache`).

The "update available" chip is driven by `git ls-remote` against the deployed
commit (`ulrmm/utils.py`, `get_remote_update_status`), not by comparing version
strings, so it lights up on any new commit on the branch and not only on a
version bump. That is the wanted behaviour for an instance that deploys from a
branch: it compares SHAs, it never reads the settings file over git.

## Version scheme

`X.DD.MM.YYYY`: the release date, day and month always two digits, and in front
of it `X`, the number of the release on that day. `X` starts at 1 and restarts
at 1 on every new day, so the first release on 1 October 2026 is `1.01.10.2026`
and a second one that day `2.01.10.2026`. No suffixes, no build metadata; the
gate rejects anything else, including dates that do not exist.

The stored string never has a `v`: `VERSION`, `package.json`,
`LATEST_AGENT_VER`, the agent's `main.go` and `setup.iss` all carry
`1.24.09.2026`. The `v` appears only where something is shown or named: the
dashboard (`v1.24.09.2026`), artifact names (`ulrmm-agent-v1.24.09.2026-linux-amd64`)
and git tags. A stored `v` would double it in all three.

The string does not sort as text or as semver: `2.23.09.2026` is older than
`1.24.09.2026`. Only the server orders versions, and it does that through one
helper, `agent_ver()` in `api/ulrmm/ulrmm/helpers.py`, which maps
`X.DD.MM.YYYY` to `YYYY.M.D.X`. Every agent version comparison goes through it
(update filters, the installer check, the feature thresholds). The dashboard
and the shell scripts only compare for equality.

Windows needs a numeric version of at most four parts, each up to 65535, for the
file version and the installer's `VersionInfoVersion`. It gets the same mapping,
`YYYY.M.D.X` (`2026.9.24.1`), which `build_agents.sh` derives from the version
and hands to `goversioninfo` and to ISCC as `MyAppNumVersion`. The installer's
`AppVersion`, the text shown in "Apps & features", is `v1.24.09.2026`.
npm accepts the string as it is in the private web package; no numeric form is
needed there.

`riddix/scripts/check_versions.py --next` prints the next version (`X+1` for a
second release on the same day, otherwise `1.<today>`), `--next agent` does the
same for `LATEST_AGENT_VER`.

### Compatibility rules

| Pair | Rule |
|---|---|
| Server ↔ web | Same version, always. `update.sh` builds the SPA from source on every deploy, so they are physically deployed together; the equal version string is the label on that fact and a check that both branches were actually tagged. |
| Server ↔ agent | Independent version lines. The server must keep working with any agent from `LATEST_AGENT_VER` back to the oldest one still in the field, because agents update themselves asynchronously and an offline machine can be weeks behind. Never require an agent newer than `LATEST_AGENT_VER`. |
| Agent ↔ agent | `update_agents` only touches agents strictly below `LATEST_AGENT_VER` in `agent_ver()` order. A rebuild that keeps the same version (re-signing, branding) never reaches the fleet through the normal path — that needs "Push Current Build to All Agents" (`do_update(force=True)`). |
| Web ↔ agent | None. The dashboard displays agent versions, it does not depend on them. |

## The gate check

```
python3 riddix/scripts/check_versions.py --web ulrmm-web --agent ulrmm-agent
```

Standard library only, no Django, no imports of `settings.py` — it parses the
file with `ast`, because the gate container has no configured Django. It
verifies:

- `VERSION` exists and is `X.DD.MM.YYYY` with a real date
- `settings.py` derives `ULRMM_VERSION` from `VERSION` instead of assigning a
  literal (a literal is reported even when it happens to match — a second source
  is the defect, not the drift). The *last* module level assignment is the one
  judged, because that is the one the import ends up with
- `settings.py` is readable and parses — a broken file is one row in the table,
  not a traceback
- `LATEST_AGENT_VER` is a literal in the same format
- `--web`: `package.json` version equals `VERSION`
- `--agent`: `main.go` version and `build/setup.iss` `MyAppVersion` both equal
  `LATEST_AGENT_VER`

Exit code 1 with a table of mismatches, 0 and one line otherwise. `--web` and
`--agent` are optional, so the check is useful with only the server tree
checked out.

Tests: `riddix/scripts/test_check_versions.py` (stdlib `unittest`, builds fake
trees in a temp directory, and covers `--next`), `TestVersionFile` in
`api/ulrmm/ulrmm/tests.py`, which asserts that `settings.ULRMM_VERSION` really
is the content of `settings.VERSION_FILE`, and `TestAgentVer` next to it for the
ordering.

On the web side, `npm run check:version -- <path to the server tree>` compares
`package.json` against the server's `VERSION`. Without a path it prints a line
and passes, because the server tree is not always checked out next to the web
one.

`update.sh` runs the same comparison at deploy time against the *fetched* web
tree and only warns (`WEB_PKG_VER`); `install.sh` and `restore.sh` do the same in
`build_web`. The two repositories are fetched separately; a label mismatch is a
packaging mistake, not a reason to leave the dashboard unbuilt.

## Agent version line

The agent has a version of its own in the same format. It changes only when the
agent changes, so the agent and the product version share a date only when both
were released that day. It started at `1.24.09.2026`, the same day as the
product.

Agents from before the date scheme report `MAJOR.MINOR.PATCH`. `agent_ver()`
sorts every one of those below every dated version, which has three effects:

1. **The fleet moves on by itself.** `update_agents` (hourly) and
   `agents/views.py` target agents whose version is strictly lower than
   `LATEST_AGENT_VER`. Every old-scheme version is lower than `1.24.09.2026`, so
   the change of scheme needs no forced update.
2. **The feature thresholds keep working.** `agents/utils.py`
   (`get_validated_agent`), `agents/consumers.py`, `agents/views.py`,
   `autotasks/views.py`, `core/tasks.py`, `agents/models.py` and
   `winupdate/tasks.py` still compare against minimum versions of the old
   scheme, and every dated agent passes all of them. New gates for new agents
   should check what the agent reports instead of a version.
3. **A malformed report sorts lowest** instead of raising: `natsapi` stores the
   agent-reported string unvalidated, and `agent_ver()` falls back to `0`.

Two agent releases on the same day need different `X`; with the same string the
second one only reaches agents through "Push Current Build to All Agents"
(`do_update(force=True)`).

## Blockers and open points

| # | Item | Impact |
|---|---|---|
| 1 | Agent versions arrive unvalidated | `natsapi/svc.go` (`agent-hello` handler) writes the agent-reported string straight into `Agent.version`. `agent_ver()` sorts a malformed one lowest, so it no longer raises, but the string is shown as reported. |
| 2 | CI does not run `check_versions.py` | `.github/workflows/ci-tests.yml` runs on GitHub, but `check_versions.py` is not part of it. That gate is run by hand (`README.md`, Development and gates). |
