# Server changelog

## 2.07.11.2026 (2026-11-07)

- agents update to 1.07.11.2026
- INSTALL_NUSHELL_SHA256 and INSTALL_DENO_SHA256 settings: the sha256 of a custom runtime download; the agent now refuses a runtime without a sum, so a custom INSTALL_NUSHELL_URL or INSTALL_DENO_URL needs it

## 1.07.11.2026 (2026-11-07)

- deleting a client or site with a target site drops the merged policy checks, tasks and baselines of the moved devices at once; before, the old merge could stay for up to ten minutes and reach the device on its next sync
- /etc/letsencrypt stays owned by root; the service user reads live/ and archive/ through its group, and update.sh repairs existing hosts; an own key kept under /etc/letsencrypt outside live/ and archive/ leaves the tree as it is
- restore.sh refuses a backup whose outer archive holds links or special files, moves a non-empty /etc/letsencrypt aside instead of deleting it, checks the restored domains before they reach nginx, and takes --resume to continue after a failed run; the database and user are created only when missing
- install.sh, restore.sh and update.sh check the fingerprint of every apt signing key before trusting it, fetch the nginx repository over https, and no longer upgrade npm to its latest version
- an imported device without a site is marked failed with the reason instead of staying "Not sent" without an error
- report data sources with the client property load the client with the rows instead of one query per row
- Windows deployment credentials, OU and image name refuse control characters, which made the answer file unreadable for Windows Setup
- a command frame that fails to decrypt no longer moves the agent session to its epoch; a broken agent could pin its own session at the limit and block commands until the session expired
- two image uploads with the same name at the same time give one "exists already" error instead of a damaged row and a server error; a built image whose move to the library fails leaves no library row and no leftover file
- image and checksum downloads connect to the address that passed the private-network check, so a name that changes its address between the check and the download is refused; a release check does the same
- removed two unused deployment helpers and three duplicate helpers in vault and encryption; the install library tests run in CI

## 1.04.11.2026 (2026-11-04)

- update.sh installs packages, Python, nats-server, npm and the MeshCentral modules before it stops the services, so a failed download no longer costs a stop and start; a MeshCentral the update stopped is started again when the update fails
- backup.sh lists the ISO images of the image library in MANIFEST and packs them with --with-large-packages; restore.sh names the images it did not get back
- adding, editing or deleting an SSO provider needs a fresh two-factor code and only a role the actor could grant; API keys are refused
- built ISO images are listed, linked and deleted only within the site scope of the deployment they were built for; built images from before this release need superuser rights
- policy checks and tasks are merged per device, so a device excluded from a policy no longer shares the result of its site neighbours; moving a device to another site or policy takes effect at once
- a Windows patch window stays open for the next hour when the install command could not be sent, and the attempt is logged
- a vulnerability whose advisory arrives on a later scan is still notified
- script runs that wait for output, script and server script test runs and raw commands are limited to 290 seconds, the time a request may take; longer runs use the email or background option
- completed pending actions are pruned with the debug log retention
- the scheduled task runner claims each task once per minute, also under worker backlog
- a failed NATS configuration write after a token grant is logged instead of failing the enrolment
- app updates left in "updating" by a worker restart are picked up by the next run
- auto-approval errors and a failed Dell warranty login are logged once instead of repeated per device
- removed unused cache helpers and constants, the pyparsing, six and zipp pins

## 2.03.11.2026 (2026-11-03)

- agents update to 2.03.11.2026: a Mac can stay awake on AC power (Keep awake, Stay awake on power), lid closed included, and sleeps as usual on battery; unplugged with the lid closed it goes to sleep; the setting survives agent restarts
- POST /agents/<id>/keepawake/ takes {"ac": true|false} for that setting, macOS only and agent 2.03.11.2026 or newer, recorded in the audit log
- uninstalling an agent puts back the sleep and lid settings a keep awake hold changed

## 1.03.11.2026 (2026-11-03)

- licenses show which Windows devices use a stored Microsoft key: every night at 04:50 the online Windows devices report their Windows and volume-licensed Office activation (product, channel, last five key characters, status), and a key in a license matches by its last five characters; offline devices keep their last report
- a license lists its matching devices as activated or not activated, and with a seat count also how many seats are free

## 3.02.11.2026 (2026-11-02)

- the import source for servers with the same REST API is now called Compatible RMM server
- documentation site built from README.md and docs/ (riddix/scripts/docs_site.py, workflow Docs site); it deploys to GitHub Pages once the repository is public and Pages uses GitHub Actions as its source

## 2.02.11.2026 (2026-11-02)

- import from another RMM (Global Settings > Import, superusers): clients, sites, devices, custom fields, scripts, snippets and key store from a compatible RMM server or NinjaOne, with a preview before anything is written; existing entries stay, a second run adds nothing
- imported devices link to their agent when it enrolls in the same site (or with Link enrolled agents) and bring description, notes and custom field values along
- Send installer runs the agent installer on the devices through the old RMM: Windows and Linux with a deployment link made for the run (3 days, capped at the number of devices), macOS with a 3-day install token; unused links and tokens are deleted

## 1.02.11.2026 (2026-11-02)

- agents update to 1.02.11.2026, built with Go 1.27.3 (GO-2026-6809, crypto/x509 certificate verification)
- the agent and natsapi build toolchain is Go 1.27.3 (pinned SHA-256)
- Django 5.2, DRF 3.18, django-allauth 65.21 and weasyprint 70; the API keeps its previous validation and error texts

## 5.01.11.2026 (2026-11-01)

- agents update to 2.01.11.2026, which announce orderly shutdowns, restarts and sleep (tested live on Windows 11: restart, RMM restart, sleep, Fast Startup shutdown)

## 4.01.11.2026 (2026-11-01)

- natsapi stores agent-agentinfo check-ins again: 3.01.11.2026 compared boot_time as bigint while the column is double precision, so PostgreSQL rejected every info update (hostname, OS, RAM, boot time, pending reboot, logged-in user)

## 3.01.11.2026 (2026-11-01)

- agents can announce an orderly shutdown, restart or sleep before they go away (check-in mode agent-power); natsapi stores kind, server time and initiator
- an agent silent after such an announcement stays offline, never overdue, and raises no outage or tamper alert until it is back
- reboot, shutdown and sleep sent from the dashboard, bulk sleep, patch reboots and sleep or maintenance schedules record the same event with the user or schedule, also for older agents
- the event ends with a check-in after a new boot, a hello one minute after a sleep, or a cancel from the agent
- agent table, agent detail and the remote control pop-outs return power_event, power_event_at, power_event_by and planned_offline
- the Linux agent unit stops before the network and gets a 15 s stop timeout
- a failed patch counts at least one attempt in the patch records

## 2.01.11.2026 (2026-11-01)

- failed patch options apply: schedules and maintenance windows retry a failed update only with reprocessing on, up to the set number of times; Install now still sends every approved update
- failed installs are counted per update (fail_count), a success resets the count, the patch records mirror it as attempts
- a policy with email on failure sends one mail per device and run listing the failed updates
- pacman updates skipped because not all pacman updates were approved no longer count as failed
- an agent is overdue only while outage monitoring watches it (own overdue alert or alert template); otherwise a silent agent stays offline, so shut down devices no longer raise overdue
- stats, widgets, group rules and the dashboard alert icon follow the same rule
- online checks no longer load the alert template of each agent

## 1.01.11.2026 (2026-11-01)

- deleting a role that users still hold is refused with 400
- users list and user detail return a read-only is_superuser
- dashinfo returns is_superuser to allow the web interface to hide superuser-only entries
- Add User stores Active and Deny Dashboard Logins
- dashboard colors are checked against the names the dashboard can show and unchanged old values still save
- send command and bulk command refuse the custom shell without a path
- task command actions refuse the custom placeholder shell and name the action
- meshcentral endpoint returns the agent platform
- alert list takes an optional agent filter
- URL action test run accepts empty body and headers and no longer parses empty fields
- deploy builder validates proxy and mirror URLs and writes the proxy for kickstart, autoyast, agama and archinstall targets
- Windows join details without a domain raise a field error
- global rotation policy saves again and a lifetime equal to the days stays linked
- report schedule time zones are validated
- template dependencies refuse the reserved names data_sources and charts, including in import
- query schema is built when the generated file is missing
- docker init generates the json schemas before collectstatic
- deleting a deployment records what was deleted in the audit log

## 2.31.10.2026 (2026-10-31)

- Windows full-build ISOs no longer fail in Setup at 6 percent with 0x8007007E; pycdlib 1.22 left UDF parent entries, extended attribute headers and the partition length at old positions, iso.inject now rewrites them
- Windows full build puts the agent under sources\$OEM$\$1, Setup ignores a root $OEM$
- scripts travel only inside autounattend.xml; C:\ulrmm is locked to SYSTEM and Administrators in specialize and deleted by the bootstrap
- Windows seed ISO no longer carries the agent, Setup ignores $OEM$ on a second drive; README and plan answer follow
- agent file on ISO media is named agent-<arch>.<ext>, long client and site names broke builds
- Debian BIOS full build no longer stops at the speech synthesis menu
- RHEL, Alma, Rocky and Fedora full builds skip the media check; boot info tables that name block 48 or 64 are updated, Alma 10 BIOS boot hung; kickstart ends with reboot --eject
- Leap and SLES autoyast loads from label:// and runs without confirmation
- isohybrid MBRs pycdlib cannot move are dropped, Leap and Arch builds crashed
- Leap base images are detected as suse with the version from the general section
- mbr_kept also checks the GPT partition array
- unattended Linux full builds note that the image installs again if left attached
- inject-iso.sh applies the same menu rules

## 1.31.10.2026 (2026-10-31)

- Web interface and agent versions update to 1.31.10.2026
- MeshCentral login and auth tokens now build with internal code
- meshctrl and pycryptodome requirements drop from the project
- Login tokens adopt the AES-GCM cookie format MeshCentral writes
- AI script draft settings rename to ai_api_key and ai_model
- Endpoint POST /core/ai/generate/ handles AI generation
- Migration core 0007 runs and stored keys still decrypt
- Built-in Gitea release source activates only when ULRMM_RELEASE_GITEA_TOKEN sets
- GitHub remains the sole source without that token
- Chocolatey package list regenerates from the community feed with 12093 packages
- Release workflow builds the dashboard in a separate job without the signing key
- release_build.sh accepts the --prebuilt flag for this build
- Cryptography packages pin to specific versions
- All workflow actions pin to commit SHAs
- Nginx image builds from the dashboard release tag
- Container images include LICENSE.md and NOTICE.md and THIRD_PARTY_NOTICES.md under /usr/share/doc/ulrmm
- Container images carry OCI license labels
- RustDesk client mirror writes SOURCE.txt with license and source details
- THIRD_PARTY_NOTICES.md documents third-party software and risks
- README sections cover outbound connections and lawful use and trademarks and contributing and sponsoring
- SECURITY.md defines the security scope
- local_settings.example.py switches to GitHub URLs
- flake8 and coverage and mypy settings rewrite with identical options

## 2.29.10.2026 (2026-10-29)

- Web interface 2.29.10.2026 and agent 2.29.10.2026
- self-heal answer for Windows agents carries agent_sha256
- Windows agents can repair a binary that does not match the build
- agent builds use -buildvcs=false
- a commit that does not change the agent code no longer changes the agent hashes
- build_agents.sh keeps the published builds of a version when a rebuild of the same version differs
- build_agents.sh warns that the agent changed without a new version
- a branding or enrollment key change or ULRMM_AGENT_REPLACE=1 replaces them
- this ends the integrity_mismatch reports of Windows agents after a server update rebuilt agent 1.27.10.2026

## 1.29.10.2026 (2026-10-29)

- Bump server to 1.29.10.2026 and agent to 1.29.10.2026
- License is FSL-1.1-ALv2 with NOTICE.md and SPDX headers in every source file
- README rewritten to include feature showcase, architecture overview and quickstart guide
- New Docker Compose deployment in docker/ with services for api, ws, celery, celerybeat, natsapi, nats, mesh, nginx, db and redis plus a one-shot init container
- Added release job to publish images to ghcr.io
- install.sh, update.sh and restore.sh default to GitHub repositories with --source gitea for the Gitea copy
- Added MESH_HOST, ULRMM_CONF_DIR and ULRMM_NATS_RELOAD settings for container setups
- SECURITY.md now points to GitHub private vulnerability reporting
- Build and RustDesk scripts are in English along with the agent build guide
- Removed two personal helper scripts
- Merged beta v1 API modules into a single file with identical routes
- Reworked nginx and systemd generators with no change to rendered configuration
- MeshCentral restarts once during the update

## 2.27.10.2026 (2026-10-27)

- Web interface 2.27.10.2026 and agent 1.27.10.2026
- Updates: new Update Center page at /updates replaces the server update dialog, shows which release source answers (GitHub first, Gitea as fallback), the installed and latest version, a live stepper (pre-flight, download with percent and MB/s, Ed25519 and SHA-256 verification, backup, apply, migration, restart, health) and reconnects to core/health/ after the restart
- Updates: releases are discovered from GitHub releases first and from Gitea when GitHub fails (connection error, non-200, bad JSON, missing asset, bad signature); every release manifest must verify against the pinned Ed25519 release key and every tarball against the manifest sha256 and size before anything is applied, the download stops when a tarball grows beyond the manifest size
- Updates: update.sh --release installs from verified tarballs (server tree and built web app) instead of git, takes a snapshot before the swap, checks core/health/ after the restart and rolls back code and web app on failure or on any error after the swap; an optional ULRMM_UPDATER_HOOK hands the update to a container or compose hook
- Updates: new endpoints core/health/, core/server/update/sources/ and core/server/update/progress/, update progress written to update.progress.json
- Release tooling: riddix/scripts/release_build.sh builds and signs the release assets, .github/workflows/release.yml publishes them to GitHub and mirrors them to Gitea
- Agent: update signatures are required. On Linux, macOS, and FreeBSD, the downloaded binary runs a selftest (mTLS handshake and core/health checks) before replacing the old one. The update is refused if the selftest fails. On Windows, the running agent runs the selftest before starting the installer. Self-heal repairs must carry the same signature. On Linux, macOS, and FreeBSD, an updated agent that does not reach NATS within ten minutes reverts to the previous binary and reports update_reverted.
- Update Center: agent fleet card shows agents below the current version and starts the rollout
- Database: migration adds the update_reverted security event kind
- Security events: update_reverted
- Maintenance: rsync and git clean no longer touch api/ulrmm/ulrmm/private (ISO library, deploy data, logs)
- Agents: GET agents/versions/ includes the agent version

## 1.27.10.2026 (2026-10-27)

- Web interface 1.27.10.2026 and agent 1.26.10.2026
- Deployment builder, base images: installation media download in the background with live progress. The library reports status, bytes, rate and remaining time per image once a second, a second request for the same URL joins the running download instead of starting another, a download that broke off resumes from the partial file, and the finished file is only released after its SHA-256 matches the checksum from the distribution's sums file or the one given by hand
- Deployment builder, base images: downloads can be cancelled and retried, the download target must resolve to a public address and stay on https across redirects
- Database: migration 0014 adds the expected checksum and the verifying state to base images

## 5.26.10.2026 (2026-10-27)

- Web interface 4.26.10.2026 and agent 1.26.10.2026
- Deployment builder, Windows media: built ISOs boot on UEFI again. Windows media list the EFI boot image with a sector count of 1 and without a directory entry, so the rewrite kept only the first 512 bytes of it; the boot catalog entry is widened to the size the FAT boot sector declares. BIOS boot was never affected
- Deployment builder, Debian: the preseed answers the boot device question of grub-installer, so unattended installs no longer stop at "Configuring grub-pc" before the first-boot enrollment is written
- Deployment builder, Linux first boot: the enrollment service waits until the server name resolves (at most ten minutes) before it installs the agent package from the media. network-online fired before the resolver was ready, the package postinst failed on "Could not resolve host" and only the download fallback enrolled the machine. A package whose postinst fails is removed again so later apt runs stay clean
- Deployment builder, Linux first boot: the enrollment service also waits for a TCP connection to the server, orders itself after systemd-resolved and NetworkManager-wait-online, and restarts every 10 seconds on failure until the agent is enrolled instead of failing once
- Deployment builder, Windows first boot: the bootstrap task waits for name resolution and the server port (up to five minutes) before every install try instead of giving up after three port checks and sleeping 15 minutes

## 4.26.10.2026 (2026-10-26)

- Web interface 4.26.10.2026 and agent 1.26.10.2026
- Deployment builder, Windows privacy: the single preset became a preset plus one switch per control (advertising ID, tailored experiences, activity history, location, assistant app, Recall, Spotlight, consumer features, web search, widgets, feedback, OneDrive, Edge diagnostic data, inking and typing, online speech, suggestions, error reporting, Cortana, Find My Device, tips, telemetry services, peer update sharing). The presets Windows defaults, Reduced and Maximum fill the switches and render exactly as before; any switch can be changed on its own. Switches an edition or release does not honour are gated the same way as before (`assistant_recall`, `client_apps` capabilities). `debloat.consumer_policy` is accepted as an alias of `privacy.consumer_content`; profiles without the switches follow their preset. Home editions at Reduced also get the tailored-experiences Settings switch
- Deployment builder, Ubuntu: 26.04 LTS and 26.10 (interim) join 22.04 and 24.04; every Ubuntu and Debian target carries release dates and end of support, shown in the builder
- Deployment builder, official images: Linux targets list the official installation media (Ubuntu Server and Desktop, Debian netinst, Fedora 44, Rocky and AlmaLinux 9 and 10, openSUSE Leap 15.6 and 16.0, Arch, CachyOS, EndeavourOS, Batocera) with size and checksum link; the builder fetches them into the image library in one click. Links are pinned as of 2026-10-26
- Deployment builder, new targets: CachyOS and EndeavourOS as archinstall profiles run from the Arch ISO with the distribution's repository, keys, mirrorlist and kernel (CachyOS kernel choice); Batocera as an experimental target that renders a `batocera.conf` fragment and a `services/ulrmm` script which enrolls and starts the agent from the SHARE partition (no unattended installer exists for Batocera; untested on hardware)
- Deployment builder, software catalog: every Linux target offers a checked catalog of packages per family (browsers, office, development, media, gaming on Arch, remote tools, system tools) with package names verified against the distribution's repositories; selections join the extra packages in the answer file
- archinstall profiles honour the package mirror field and can set kernels and repositories
- Matrix: targets may carry `release`, `downloads` and `presets`; field metadata may carry `group`, `order`, `capability` and `preset`; new field kind `checkgroup`
- Builder texts: one vocabulary across operating systems (Host name, Admin account, Extra packages), shorter labels and one-sentence help

## 3.26.10.2026 (2026-10-26)

- Web interface 3.26.10.2026 and agent 1.26.10.2026
- Image library: images the deployment builder built stay in `private/iso` as library rows (kind built, with builder and target) until deleted instead of being removed after 24 hours; a built image is never offered as a base
- Base images upload from the browser in parts (`deploy/iso/uploads/`), staged in `private/iso/.uploads`, with the same step-up, 14 GiB cap and free-space check as software packages; stale parts are pruned after a day
- Image downloads go through a link valid for ten minutes (`deploy/iso/library/<id>/link/`) that nginx serves from `private/iso`; built images need the step-up for the link. The job download that streamed through Django is gone
- nginx access log leaves the ISO download token out

## 2.26.10.2026 (2026-10-26)

- Web interface 2.26.10.2026 and agent 1.26.10.2026
- Deployment builder: ISO images are built on the server. A seed ISO (volume AUTOUNATTEND, OEMDRV or CIDATA) holds the answer file, the agent package and the signed configuration and is attached as a second drive next to the unchanged install media; a full ISO slipstreams the same files and the unattended boot entries into a base image from the new ISO library. Both keep the BIOS and UEFI boot entries of the base image and report their SHA-256
- ISO library under `private/iso`: files copied there or fetched from an https URL are hashed and inspected (label, OS family, BIOS/UEFI/UDF) in the background
- Every ISO carries `/ulrmm/config.jws`, the deployment's organisation, site, policy, enrollment token and certificate pins signed with the server's Ed25519 key, next to the public key
- Installed systems use the agent package from the install media before downloading one
- Builds run as background jobs with progress; finished images are removed after 24 hours
- Windows 11 26H2 (general availability 2026-09-29) is a selectable release and the default for new Windows 11 profiles; the Recall and assistant-app policies of 24H2/25H2 apply to it

## 1.26.10.2026 (2026-10-26)

- Web interface 1.26.10.2026 and agent 1.26.10.2026
- The dashboard's Content-Security-Policy is enforced. HTML reports and template previews open in a frame from the API host with their own policy (single-use link, valid 2 minutes, up to 32 MiB); SSO sign-in may continue to the identity provider
- Signed build manifest at `/api/v3/integrity/` with the sha256 of every agent build in the dist folder; Windows builds are listed through the new `.agent.sha256` file `build_agents.sh` writes next to each setup. Agents report `integrity_mismatch` and `config_tampered` as security events
- Trust matrix: the key store of each agent (TPM, DPAPI, Keychain, host key or file)

## 5.25.10.2026 (2026-10-25)

- Web interface 5.25.10.2026 and agent 3.25.10.2026
- Agent identity: agents from 3.25.10.2026 register an Ed25519 signing key, an X25519 key and a NATS nkey (`POST /api/v3/<id>/identity/`); a second registration with other keys is refused and recorded as an identity conflict. NATS lists registered agents as nkey users (websocket only) instead of password users, and the `/natsws/<agent id>` path admits only that agent's own client certificate
- Agent tokens are stored as HMAC digests with a pepper (`AGENT_TOKEN_PEPPERS`, created by install and update); registered agents trade the install token for a short-lived access token and a single-use refresh token. A refresh token used twice quarantines the agent (critical security event) and closes its NATS connection
- Commands to registered agents are signed with a command key listed in the pin document and encrypted per session (X25519 handshake signed on both sides, ChaCha20-Poly1305, new keys after an hour, 64 MiB or 100,000 messages); answers and stream and terminal output come back encrypted, answers signed. Package plans, self-healing data and certificates are sealed to the agent's key
- Offline recovery: an agent whose certificate or tokens expired less than 30 days ago (and were not revoked) gets new ones by signing a challenge with its identity key
- Global Settings › Agent security: sec2 mode off / optional (default) / required with coverage, command keys and their rotation, pin promotion after a certificate change; the agent certificate panel shows the identity and offers quarantine, release, reset identity, block and rotation of session, certificate, token or identity
- Agents before 3.25.10.2026 keep working in off and optional; required cuts them off
- Rotation policies: Global Settings › Agent security carries the session rekey interval and volume, the certificate lifetime in hours, the renewal point in percent, the offline recovery grace and whether a reused refresh token quarantines the agent; clients and sites override single values (`/deploy/security/policies/`). Sessions take their limits at the handshake, certificates carry `renew_pct` in the answer the agent gets; without automatic quarantine a reused refresh token is still refused and recorded
- Trust matrix (`/deploy/security/matrix/`): every agent with certificate fingerprint, expiry countdown, token rotation, pin set and a status from blocked over quarantined, clone alert, revoked, offline grace, expired and renewing to valid, filtered by host name and status
- Windows Home answer files mirror the privacy policies Home ignores in per-user settings and services (Cortana consent, feedback, inking and typing, tailored experiences, delivery optimization, error reporting) and say so in the warnings
- Deployment downloads are streamed in 64 KiB chunks with a content length

## 4.25.10.2026 (2026-10-25)

- Web interface 4.25.10.2026
- Firewall: update.sh (and install/restore) loads an nftables table `ulrmm` that lets in only established traffic, loopback, ICMP, SSH, 80, 443, 21115-21117/tcp and 21116/udp (plus the NATS port when NATS runs on its own port) and drops other inbound traffic; other tables stay untouched. A load is rolled back after 5 minutes unless the self-check confirms it; at boot the rules are rendered again with the ssh ports configured then plus those of the saved rules. `FIREWALL=off` in /etc/ulrmm/firewall.conf removes it and keeps it off, `update.sh --no-firewall` leaves it as it is for one run, `riddix/scripts/firewall.sh off` removes it
- install.sh waits for the MeshCentral start it just triggered before it creates the device group (a fresh install could end without one)
- Redis needs a password (`REDIS_PASSWORD`, created by install, update and restore)
- `riddix/scripts/rotate-secrets.sh mesh|db|redis` rotates the MeshCentral login key and mesh token, the Postgres role passwords or the Redis password and restarts what uses them; secrets never go on the command line or into the journal
- Deployment links: optional enrollment limit, the number of enrollments in the list, a 403 and a security event when a link is used past its limit; old deployment tokens are no longer stored in plain text
- Checks that have never run count as pending, not as passing
- The Linux install script checks the sha256 of the mesh agent it downloads
- The server pins are read only from the certificate chain and its issuing root, an unreadable certificate is skipped instead of emptying the list
- Python dependencies with security fixes: aiohttp 3.14.4, brotli 1.2.1, certifi 2026.10.19, filelock 4.2.1, msgpack 1.2.1, sqlparse 0.6.0, urllib3 2.8.0

## 3.25.10.2026 (2026-10-25)

- Web interface 3.25.10.2026 and agent 2.25.10.2026
- nginx: TLS 1.2 only with ECDHE and AES-GCM or ChaCha20, TLS 1.3 with AES-256-GCM and ChaCha20, key exchange X25519MLKEM768 (when nginx uses OpenSSL 3.5 or newer), X25519, P-256 and P-384; the TLS settings live in one place for every vhost. NATS over its own port needs TLS 1.3
- Signed pin document at `/api/v3/pins/` with the SPKI pins of the server certificate chain and the backup pins from Global Settings › Agent security; its sequence number grows with every change. Deployment tokens are no longer issued without pins or for an http API address
- Agent updates carry a signature over URL, version and sha256 for each agent; with `SELF_BUILT_AGENTS_URL` the server downloads the build once and hashes it, and skips the update when it cannot
- Security events: refused agent certificates, refused NATS logins, dashboard sessions past their limit, unencrypted backups and what agents report (pin mismatch, pin rescue, refused update) are kept for 90 days and listed in Global Settings › Agent security
- Agents from 2.25.10.2026 send check-ins to `<agent id>.checkin` and may no longer publish on their own command subject; NATS permissions follow agent updates within 5 minutes. The NATS websocket listens on 127.0.0.1 only
- Dashboard sessions end 12 hours after login (`DASHBOARD_TOKEN_MAX_TTL`), also when they are kept active
- Key store values, URL action headers and bodies and the users' TOTP keys are stored encrypted. Field encryption uses `FIELD_ENCRYPTION_KEYS` (created by install and update); `manage.py rotate_field_keys` re-encrypts every encrypted column with the current key, so keys and `SECRET_KEY` can be rotated
- Backups are encrypted with age when `BACKUP_AGE_RECIPIENTS` is set in backup.conf (`.tar.age`, `restore.sh --age-identity <key file>`); without recipients the backup warns and records a security event. Saving backup settings in the dashboard keeps the recipients
- Install commands hand the installer token over in a root-only file (`-auth-file`); with a self-signed server certificate they pass the certificate as `-cert` instead of the removed insecure mode; downloads in the install scripts need https. Agents that were installed in the insecure mode against an IP address or a name the certificate does not cover lose the connection after the update to agent 2.25.10.2026: reinstall them with the certificate's host name (and the certificate as `-cert` for a self-signed server) before updating
- Logs: one filter masks tokens, passwords and certificates in every Django log; nginx logs deployment links, download tokens and sign-in callbacks without their secret part, the mesh site logs nothing; failed URL actions and mesh downloads no longer return the address; the audit log keeps literal script arguments of bulk runs as markers and only exit code, run time and output size of test runs
- Script environment variables: interpreter hooks such as `PERL5OPT`, `RUBYOPT`, `JAVA_TOOL_OPTIONS`, `OPENSSL_CONF` and `GCONV_PATH` are refused

## 2.25.10.2026 (2026-10-25)

- Web interface 2.25.10.2026: dropdowns in the deployment builder
- Deployment builder, Windows: release per target (Windows 11 23H2, 24H2, 25H2; Windows 10 22H2; IoT Enterprise LTSC 2021 and 2024; Server 2019, 2022, 2025) with its image name and notes; display language, region formats, keyboard and all Windows time zones as lists; privacy level default, reduced or maximum on every edition (diagnostic data at the lowest level the edition honours, telemetry services and tasks off, advertising ID, activity history, suggestions, Spotlight, web results in Start search, the assistant sidebar, Recall and peer-to-peer updates off; the notes say what Home and Pro cannot turn off); OpenSSH server with key, password or both and the key built in; the OOBE privacy page can be shown or skipped
- Deployment builder, Linux: desktop environment per distribution, offered only where the release ships it (Ubuntu and Debian GNOME, KDE, Xfce, Cinnamon, MATE, LXQt and more; RHEL, Rocky and Alma GNOME; Fedora spins; SUSE patterns; Arch through the archinstall desktop profile up to Sway and Hyprland), with display manager, NetworkManager and the graphical target; SSH with key, password or both, keys built in for the admin (and root when root login is on); locale, keyboard and time zone as lists. Debian installs only the standard system unless a desktop is chosen, the keyboard variant reaches the installed system, SLES and Leap 15 up to 15.5 read the SSH settings, Kickstart turns sshd off when SSH is off
- Deployment links can be valid for up to 365 days, for install sticks used over months
- The matrix ships each long choice list once

## 1.25.10.2026 (2026-10-25)

- Web interface 1.25.10.2026: deployment builder, software catalog with archives and baselines, agent security settings
- Deployment links work again: `/clients/<uid>/deploy/` hands out per-deployment agent installers for Windows (setup exe) and Linux (.deb, .rpm, .tar.gz, and a shell script with a detached Ed25519 signature for `openssl pkeyutl -verify`). Each carries an Ed25519-signed enrollment token bound to client, site, agent type and automation policy, valid until the deployment expires; agent and server refuse a token that was changed, and deleting the deployment revokes it. New deployments no longer hold a knox token
- Unattended OS answer files from the builder: autounattend.xml for Windows 10/11 Home, Pro, Pro IoT, Enterprise, IoT Enterprise and Windows Server 2019/2022/2025 Standard and Datacenter (Core and Desktop), with the edition limits applied (Home: no domain join, no BitLocker; consumer-features policy only on Enterprise, Education and IoT Enterprise; diagnostic data off only on Enterprise, Education and Server; Unified Write Filter only on Enterprise and IoT Enterprise); Ubuntu autoinstall, Debian preseed, Kickstart for RHEL, Rocky and Alma 9 and 10 and Fedora, AutoYaST for SLES and Leap 15, Agama for SLES and Leap 16, archinstall. The agent installs on first boot before anyone logs in (Windows: a SYSTEM start-up task that retries until the agent has checked in), with baseline policies for disk, BitLocker or LUKS, firewall, RDP or SSH, local admin (the site's LAPS account), debloat and telemetry. Downloads are single files or a zip with inject scripts; answer-file secrets are never stored
- Agent client certificates (mTLS): an agent CA in `/etc/ulrmm/agent-ca` (created by install.sh/update.sh, kept by backup.sh and restore.sh), certificates issued at enrollment and to existing agents, renewal after two thirds of the lifetime, reset per device; modes off, optional (default) and required in Global Settings › Agent security, where required needs every agent to have shown its certificate and is refused while NATS listens beyond localhost. nginx asks API clients for a certificate and checks the NATS websocket through Django
- Agents enrolled through a deployment get the deployment's agent type and policy, a LAPS rotation within minutes and a BitLocker key collection after half an hour
- Software catalog: archive packages (.zip, .7z, .tar.gz) with a setup command, exit codes and a detection rule; uploads of any size in 32 MiB parts that resume; large packages are downloaded by the agent itself with resume and sha256 check
- Software baselines: lists of winget, Chocolatey, hosted and Linux packages per automation policy or deployment. Agents install what is missing after setup, the server checks every item (inventory, file or registry rule), retries failed ones and checks installed ones again every day
- backup.sh leaves package files above 1 GiB out unless `--with-large-packages` and lists them in the MANIFEST
- The PowerShell install method checks the sha256 of the setup exe; Linux and macOS install commands keep their sha256 pin when SELF_BUILT_AGENTS_URL is set
- install.sh 99, update.sh 179, restore.sh 73, backup.sh 38

## 1.24.10.2026 (2026-10-24)

- Web interface 1.24.10.2026: right-click menus of the device list, the client tree, report templates, policies and scripts stay on screen
- Bulk action audit entries list the agent hostnames in a fixed order

## 2.21.10.2026 (2026-10-21)

- FreeBSD agents (amd64, arm64; tested on 14.4): install script for `sh` with sha256, ELF and architecture checks, rc.d service, self-healing through `/etc/cron.d`, MeshCentral agent on amd64 (it needs procfs, the agent adds the `/proc` line to `/etc/fstab`). Services, file logs (`/var/log/messages`), processes, terminal and commands with `sh`, performance history, system state (rc.d, ZFS, gmirror, graid, sysctl sensors), service checks, package inventory and updates with `pkg`, vulnerabilities from the FreeBSD VuXML database (`pkg audit`, severity unknown). New global default shell for FreeBSD. pfSense, OPNsense and TrueNAS CORE are refused by the installer
- TrueNAS SCALE: the Linux installer detects it and installs under `/root` (the rest of the system is read-only or replaced on every TrueNAS update); a POSTINIT init script restores the agent, its timer and the mesh agent after an update. Package scans and installs are refused ("package updates are managed by TrueNAS"); the inventory still works
- macOS install command checks the sha256 of the download when the server has it
- Fleet "Scan all" also queues a package scan on online FreeBSD agents

## 1.21.10.2026 (2026-10-21)

- Policy status of a check or task lists every agent it applies to, also before the first result ("Awaiting First Synchronization")
- A policy that reaches no agent is visible and editable only for roles that see every client, site and agent it is assigned to; a policy in a server default slot only for unrestricted users. Unassigned policies stay open, so a restricted role can still create one and assign it
- Editing an agent checks the chosen policy the same way as client and site edits ("You cannot assign this policy.")
- SMS test: network errors are reported as a message instead of an error 500; SMS requests time out after 15 seconds, a failed SMS alert is sent again on the next run as before
- Copying a policy copies its checks and tasks in their order (the order depended on the database before)
- Agent 1.21.10.2026 is the current agent version

## 7.20.10.2026 (2026-10-20)

- SDIO: fleet-wide list of newer pack drivers for the devices in the user's scope; progress of the index refresh (phase and counts), of the Microsoft Update Catalog check and of pack downloads (agent 7.20.10.2026)
- Overview widget "Actions" with pending and recently completed actions, optional client filter; pending count for the menu
- Agent 7.20.10.2026 is the current agent version

## 6.20.10.2026 (2026-10-20)

- Python is built with liblzma; the update rebuilds a Python without the lzma module (5.20.10.2026 stopped at the migration on such servers)
- The SDIO index reader loads lzma only when it reads, so a missing module cannot take the server down

## 5.20.10.2026 (2026-10-20)

- Drivers: SDIO driver pack indexes are fetched once a day from SDIO's web seed (only renamed index files, every piece checked against the torrent's SHA1 hashes where the seed has the neighbouring files) and matched against the driver lists of the Windows agents; newer drivers show per device, marked "BitTorrent only" when the seed does not serve the pack
- Drivers: fleet-wide approval of an SDIO driver version per hardware id (unrestricted role with package install permission and the two-factor step-up); approved drivers install on every matching agent from 5.20.10.2026 on whose patch policy does not exclude drivers, one job per agent, failed installs wait a week, installed ones are never sent again
- The package install script installs a driver folder the agent unpacked itself (signed drivers only, folder below ProgramData)
- Agent details list their patch policy rows in a stable order
- Agent 5.20.10.2026 is the current agent version

## 4.20.10.2026 (2026-10-20)

- Agent 4.20.10.2026 is the current agent version (winget without a signed-in user)

## 3.20.10.2026 (2026-10-20)

- Software: winget packages next to Chocolatey; the winget catalog is refreshed daily from the official index and searched on the server; installs need agent 3.20.10.2026 and report their exit code
- Drivers: daily check of the Microsoft Update Catalog per hardware id (cached a week, slow and polite), newer driver versions shown per device; one-click install downloads the cab from Microsoft's download hosts, checks Microsoft's checksum and installs it as a driver package
- Driver removal output keeps umlauts
- App update ids with characters such as & ! @ + are accepted
- Agent 3.20.10.2026 is the current agent version

## 2.20.10.2026 (2026-10-20)

- Removing a driver drops it from the device's driver list right away
- Agent 2.20.10.2026 is the current agent version

## 1.20.10.2026 (2026-10-20)

- Vulnerabilities: findings are split into "needs update" (a fixed version exists for the device's own release) and "no fix yet"; summaries, device counts and notifications count only findings with an update; device counts are computed on the server, so devices with more than 1,000 findings show the right numbers
- Windows drivers: daily driver and problem-device inventory per agent, refresh on demand, removal of driver packages installed as packages (never built-in drivers, never boot-critical classes)
- Windows Update: driver updates are scanned and listed as drivers; patch policies get a driver setting (off for existing policies); driver rows without a KB are kept
- Software packages: new kind "driver" (.zip or .cab with INF files) installed with pnputil, catalogs signature-checked, archive paths and sizes checked
- Agent 1.20.10.2026 is the current agent version

## 3.19.10.2026 (2026-10-19)

- Agents push a state document every five minutes (system units, mounts, time sync, RAID, sensors, network interfaces, containers and virtual machines, performance); the server keeps the latest state per agent and one metric sample per push
- Metric history: samples now carry named series (CPU, memory, swap, load, per-mount usage and inodes, per-interface rates and errors, temperatures, time offset, per-container CPU and memory, VM counts); new endpoints for the latest state, the series catalog and downsampled series; retention is a global setting (default 30 days)
- New check types: systemd unit, container, and metric threshold (warning and error thresholds above or below, averaged over N samples, judged on every push); policies, alert templates and failing-task actions work with them
- The old five-minute remote sampler skips agents that push state; it keeps sampling older agents
- Site and client warning flags no longer depend on row order when several agents report problems
- Agent 1.19.10.2026 is the current agent version

## 2.19.10.2026 (2026-10-19)

- No changes here; version kept in step with the other components

## 1.19.10.2026 (2026-10-19)

- Web interface rebuilt file by file with the same look and behaviour (see the web changelog)
- Dashboard info tells the web app whether the user may run policy tasks on demand

## 3.18.10.2026 (2026-10-18)

- Changes to other accounts and to roles need a current code from your authenticator app: password and two-factor resets of other users, API keys of other users, creating, editing and deleting roles, and changing another user's role, active state or dashboard block; API-key callers cannot do these at all
- Users and roles can only grant permissions and client or site scope they hold themselves; superusers are not limited
- Client- and site-restricted roles see only debug log lines of agents in their scope
- Installing Windows updates with nothing approved answers 400 and sends nothing to the agent; an unknown update guid answers 400
- A second patch policy for the same policy answers 400
- Role superusers are exempt from "block local user logon" like the built-in superuser
- Cancelling a reboot that already ran deletes the entry without contacting the agent
- Test suite rebuilt: 1,790 generated endpoint and task tests from the parity bench replace the old suite; the web app gains the code prompts for the account changes above

## 2.18.10.2026 (2026-10-18)

- Database migrations rebuilt as one squashed set per app; existing installs record them without any schema change, new installs run them from scratch. Installs must be on 1.18.10.2026 or newer before this update; going back to an older version afterwards needs a backup restore
- Audit log and debug log get indexes on time and agent, searches stay fast as the tables grow
- Older audit rows that still held script environment values in clear are masked
- One custom field value per client, site and agent, one software inventory per agent, one open alert per check or task; duplicates are merged on update
- Global key store names are unique; a second key with the same name answers 400
- Disk checks accept mount paths up to 255 characters
- Script snippet changes are audited like other objects (object type "scriptsnippet")

## 1.18.10.2026 (2026-10-18)

- Accounts, clients, policies, scripts, software, Windows updates, services, audit log, nats-api and the server scripts re-implemented; endpoints, database tables and agent messages are unchanged
- The dashboard web app is unchanged in this release
- Client- and site-restricted roles only see and change policies that reach agents in their scope; they cannot assign such policies, exclude foreign agents or move a site to a client outside their scope
- Running a policy task needs the permission to run tasks and runs only on agents the active policy applies to
- Blocking or disabling a user ends all its sessions at once, and blocked users can no longer use an existing session; the last active superuser cannot be disabled, blocked or deleted
- Password and two-factor resets, from the dashboard or with reset_password and reset_2fa, end the user's other sessions and API keys; the commands fail for unknown users
- API keys cannot belong to agent or installer accounts; an API key saved without an expiry date expires after 90 days
- Only superusers can end superuser sessions; ending a session is audited and the user's other sessions need the two-factor step-up again before MeshCentral terminal and files
- Malformed requests answer 400 with a short message instead of a server error across accounts, clients, deployments, policies, scripts, software, services, Windows updates and the audit log
- New audit rows for failed logins, ended sessions, cancelled pending actions, snippet changes, software installs, service actions and deployments; a change is rolled back when its audit row cannot be written
- Script environment values are masked for roles without script management and in audit rows; URL action audit rows show only scheme and host
- Deleting a script still used by checks, tasks or alert templates is refused and says where it is used; two snippets on one line are both expanded; script tests need keystore rights for global values
- Software installs need a valid chocolatey package id; duplicate software inventory rows are cleaned up
- Agent API: mesh node ids must be hex and cannot be taken from an agent of another site or from an online agent (cloned images); agent registration checks its fields and is throttled; agents reach only their own config and results
- Windows update scans skip malformed items, drop links that are not http(s) and cap text length; oversized software, disk and service lists are refused or cut
- nats-api stores over-long or invalid text cleaned and cut instead of dropping the whole update, and waits up to 5 minutes for the database at start
- install.sh and restore.sh support Debian 12/13 and Ubuntu 22.04/24.04; a failing install or restore step stops with an error instead of carrying on
- backup.sh adds a manifest and SHA256 checksums, never leaves a partial archive, needs passwordless sudo and refuses a second run at the same time
- restore.sh checks checksums, archive contents, database dumps and certificate paths before it changes the host, drops certbot hooks from the archive and restores the backup schedule
- MeshCentral location lookup is switched off on new and updated installs
- The Linux agent installer stops with an error when the agent install fails, refuses plain http download links and removes itself afterwards
- update.sh refuses an older version unless --force is given, stops on unknown options (--help lists them), refuses a second update at the same time and on a failed step prints the pre-update backup and the restore command

## 2.17.10.2026 (2026-10-17)

- Holders of "Manage Server Updates and Backups" can download server backups too, with the two-factor step-up; every download is audited

## 1.17.10.2026 (2026-10-17)

- Server update from the dashboard: the new-version notice and Help > Server update show the changes of the new version and start the update; the log follows live through the restart
- Server backups in the dashboard (Settings > Server Backups): sortable list, back up now, delete, download (superusers only), nightly schedule and retention per type
- update.sh takes a backup before every update (kept in /rmmbackups/pre-update); --no-backup skips it
- backup.sh reads its schedule and retention from /rmmbackups/backup.conf; --schedule replaces its crontab line instead of adding one and can switch the schedule off
- New role permission "Manage Server Updates and Backups"; every action needs the two-factor step-up and is audited
- Fresh installs schedule nightly backups

## 1.14.10.2026 (2026-10-14)

- Latest agent 1.14.10.2026: process list on macOS shows names and memory, process CPU is the current share of the whole machine

## 1.13.10.2026 (2026-10-13)

- Agents, core, alerts, checks, automated tasks and the server's shared modules re-implemented; endpoints, database tables, agent messages and management commands are unchanged
- Integration secrets (SMTP password, Twilio token, MeshCentral token, OpenAI token) are stored encrypted and no longer kept in the settings cache; existing values are encrypted by migration
- Client- and site-restricted roles only see and change policy checks and tasks of policies that reach agents in their scope
- Server scripts run with a minimal environment; URL actions refuse internal and reserved addresses and encode agent values; API keys need the same step-up as the dashboard for server-type alert templates
- Alert template environment values are masked for roles that cannot manage templates and in the agent details
- Alert notifications and actions are claimed atomically, so they are not sent twice; alert actions from check and task results run in a background task
- Snoozed alerts send no mail, SMS or action; resolving never creates a new alert
- Invalid input returns 400 instead of a server error across agents, alerts, checks and tasks; registry changes, process kills, recoveries and maintenance actions are audited
- MeshCentral wake-on-LAN works again; tasks created by earlier versions are still synced and removed on the agents
- SMTP STARTTLS verifies the server certificate

## 5.11.10.2026 (2026-10-11)

- Agent 3.11.10.2026 is the latest agent version (dependency update, no known vulnerabilities)

## 4.11.10.2026 (2026-10-11)

- Agent 2.11.10.2026 is the latest agent version; the agent build toolchain is Go 1.27.2 and clears the known net/http, HTTP/2, TLS and text vulnerabilities

## 3.11.10.2026 (2026-10-11)

- Agent 1.11.10.2026 is the latest agent version and rolls out to the fleet

## 2.11.10.2026 (2026-10-11)

- Agent check-in config carries sha256 digests for the nushell and deno downloads and for a chocolatey install script mirrored on the server; agents verify downloads against them
- Agents with nobody logged in are shown the same way on every platform; natsapi no longer blanks the last logged-in user of Linux and macOS agents
- Streamed command output: the server subscribes before it publishes the command, so output of fast commands is no longer lost
- Registry browsing clamps page numbers and page sizes; path search pages through all results
- Terminal output with a split multi-byte character no longer breaks the dashboard decode

## 1.11.10.2026 (2026-10-11)

- About panel in the Help menu with versions, changelogs and donation links
- Single sign-on and reporting rebuilt as own apps; SSO sign-in now works end to end
- Reporting: role scope on every data query, relation and dependency; secret fields are no longer readable from templates; stricter asset uploads and serving; PDF rendering only loads report assets; schedules have an owner whose scope they run with; history is shown per user
- Report history from before the update is linked to the users who ran it

## 3.09.10.2026 (2026-10-09)

- No changes here; version kept in step with the other components

## 2.09.10.2026 (2026-10-09)

- Audit save for singletons created with a preset primary key

## 1.09.10.2026 (2026-10-09)

- App updates, notification channels, vulnerabilities for Windows and macOS, local admin rotation, assets and licenses, UniFi and OPNsense sync, agent protection

## 2.08.10.2026 (2026-10-08)

- Harden accounts, scripts, server actions, audit and the install templates

## 1.08.10.2026 (2026-10-08)

- RustDesk release check, server update and client pin from the dashboard

## 5.07.10.2026 (2026-10-07)

- Check downloads in the Linux installer before replacing the agent

## 4.07.10.2026 (2026-10-07)

- Keep devices awake from the dashboard, lid included

## 3.07.10.2026 (2026-10-07)

- Sign macOS agents with a fixed identifier

## 2.07.10.2026 (2026-10-07)

- Performance history, tags and groups, timeline, discovery, vulnerabilities, vault, recovery keys, dashboard widgets and POSIX management

## 1.07.10.2026 (2026-10-07)

- Device display name, pushed to MeshCentral

## 1.06.10.2026 (2026-10-06)

- Own script library, typed script variables and library sync

## 1.27.09.2026 (2026-09-27)

- Default agent double-click to the device page and move the old default

## 2.26.09.2026 (2026-09-26)

- Mark updates installing and clear them on results, check-in or timeout

## 1.26.09.2026 (2026-09-26)

- No changes here; version kept in step with the other components

## 3.25.09.2026 (2026-09-25)

- Software packages, Mac script and NATS fixes

## 2.25.09.2026 (2026-09-25)

- Agent 2.25.09.2026

## 1.25.09.2026 (2026-09-25)

- Maintenance Windows, endpoint health, network monitors and RustDesk client updates

## 2.24.09.2026 (2026-09-24)

- Send every reported Mac in the wake packet

## 1.24.09.2026 (2026-09-24)

- First release under the UniversalLocal RMM name

