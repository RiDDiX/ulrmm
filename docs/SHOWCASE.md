# UniversalLocal RMM: feature showcase

The screenshots are from version 3.09.10.2026, agent 2.09.10.2026. Self-hosted remote monitoring and management with agents for Windows, Linux, macOS and FreeBSD/TrueNAS.

UniversalLocal RMM is a self-hosted remote monitoring and management system. The server is a Django API with a Vue 3 dashboard, the endpoints run a Go agent, and remote access goes through MeshCentral, which the installer sets up, and, optionally, a self-hosted RustDesk server.

Device data, scripts, credentials and recovery keys are stored on your own server. Outside services are contacted for update checks and downloads and by the features that need them, such as vulnerability feeds, warranty lookups and notification channels; README.md lists them under Outbound connections.

| | |
|---:|:---|
| **3** | platforms: Windows, Linux, macOS |
| **216** | scripts in the script library |
| **9** | check types |
| **7** | notification channel types |
| **11** | Linux/macOS package managers |
| **88** | permission flags per role |

> All screenshots come from a demo installation of version 3.09.10.2026 with fictional companies and sample data. Supported agent platforms are Windows, Linux, macOS and FreeBSD/TrueNAS. The device nw-app01 is a real Linux agent (Debian 12) connected to that installation: its terminal, process list, services, logs, script output, live CPU/memory and patch list are real agent output. The other devices are sample data written through the server's own models and parsers.

PDF versions: [English](UniversalLocal-RMM-Showcase-EN.pdf), [Deutsch](UniversalLocal-RMM-Showcase-DE.pdf).

## Contents

1. [Sign-in and two-factor authentication](#signin)
2. [Overview board](#overview)
3. [Devices workspace](#devices)
4. [Device page](#device)
5. [Remote access](#remote)
6. [Scripts and script library](#scripts)
7. [Checks, tasks and policies](#checks)
8. [Alerts and notifications](#alerts)
9. [Patch management and app updates](#patches)
10. [Software inventory and packages](#software)
11. [Vulnerabilities, encryption and credentials](#security)
12. [Assets and licenses](#assets)
13. [Network monitoring, discovery and integrations](#network)
14. [Performance, history and timeline](#history)
15. [Groups, tags and roles](#access)
16. [Agents](#agents)
17. [Reporting](#reporting)
18. [Branding, RustDesk and dark mode](#branding)

<a id="signin"></a>

## 1. Sign-in and two-factor authentication

Local accounts always sign in with a password and a TOTP code. Single sign-on through OpenID Connect providers is available as well.

- Two-factor login is mandatory; new users set it up in a dialog on the sign-in page.
- Terminal and file browser ask for a TOTP code once and stay unlocked for 60 minutes.
- Deleting an agent, client or site needs the exact name and a fresh TOTP code, checked by the server.
- Revealing vault secrets, recovery keys and license keys asks for the code as well.

![Sign-in page](showcase/login.png)
*Sign-in page*

![Second step: the TOTP code](showcase/login-2fa.png)
*Second step: the TOTP code*

<a id="overview"></a>

## 2. Overview board

Each user builds a personal board from 14 widget types. Changes are saved per user; one click restores the default board.

- Widgets: fleet, alerts, offline devices, patches, checks, activity, vulnerabilities, network devices, top CPU, top memory, discovery, groups, encryption and notes.
- Each widget only shows data the user's role is allowed to see.

![Overview board](showcase/overview.png)
*Overview board*

<a id="devices"></a>

## 3. Devices workspace

One table for every client and site, with status, checks, patch state and tags at a glance.

- Filter by client and site, switch between all devices, devices that need attention, servers and workstations.
- Quick filters for failing checks, pending or failed patches, pending actions, reboot needed, online, offline and overdue.
- Choose columns and export the table as CSV.
- Fleet health summarises failing checks, overdue agents, pending patches, active alerts, last check-in and agent versions.
- A click opens a side panel with Remote control, Terminal and Run script; a right-click opens the full action menu.

![Devices](showcase/devices.png)
*Devices*

![Fleet health](showcase/devices-fleet-health.png)
*Fleet health*

![Side panel of a device](showcase/devices-quick-panel.png)
*Side panel of a device*

![Action menu](showcase/devices-action-menu.png)
*Action menu*

<a id="device"></a>

## 4. Device page

Double-clicking a device opens its own page with everything about it on 16 tabs.

- Overview: live CPU and memory, disks, hardware, network with Wake-on-LAN readiness, asset and warranty, security, hardware health and system.
- Security: antivirus and Defender state, signature age and firewall; on macOS also Gatekeeper, SIP and FileVault.
- Hardware health: SMART/NVMe wear and temperatures, battery wear and cycle count.
- Switch, port and VLAN appear when a UniFi or OPNsense integration knows the device.
- Tabs: Overview, Performance, Checks, Tasks, Patches, Software, History, Notes, and under More: Apps (macOS), Vulnerabilities, Timeline, Vault, Assets (Windows), Encryption, Debug and Audit.

![Windows laptop](showcase/device-overview-windows.png)
*Windows laptop*

![MacBook](showcase/device-overview-macos.png)
*MacBook*

![Linux server (real agent)](showcase/device-overview-linux.png)
*Linux server (real agent)*

<a id="remote"></a>

## 5. Remote access

Take control of the desktop through MeshCentral, VNC or RustDesk, or work in the background without disturbing the user.

- Remote background: terminal, file browser, services, processes, event log (Windows), logs from journalctl or log show (Linux/macOS) and registry (Windows).
- The terminal runs through the agent itself or through MeshCentral.
- RustDesk: deploy or reconfigure the client from the action menu and connect to it; the server can also run its own RustDesk server.

![Terminal (real agent)](showcase/remote-terminal.png)
*Terminal (real agent)*

![Processes with live refresh](showcase/remote-processes.png)
*Processes with live refresh*

![systemd services](showcase/remote-services.png)
*systemd services*

![journalctl logs of the agent service](showcase/remote-logs.png)
*journalctl logs of the agent service*

<a id="scripts"></a>

## 6. Scripts and script library

A library of 216 ready-made scripts (109 for Windows, 74 for Linux, 33 for macOS) plus your own scripts, run on one device or many.

- Six shells: PowerShell, Batch, Python, Shell, Nushell and Deno.
- Typed script variables (text, numbers, checkbox, selection, IP, date, password and more), snippets, favourites and a test run.
- Output can be shown, emailed, saved to a custom field or saved to the device notes.
- Bulk command, bulk script, bulk patching and bulk package install for a client, site, group or a selection of devices.

![Script manager with the library](showcase/script-manager.png)
*Script manager with the library*

![Script run with real output](showcase/run-script.png)
*Script run with real output*

![Bulk script wizard](showcase/bulk-script.png)
*Bulk script wizard*

<a id="checks"></a>

## 7. Checks, tasks and policies

Checks watch the device, tasks act on schedules or failures, and policies roll both out to whole clients or sites.

- Nine check types: disk space, ping, CPU load, memory, Windows service, script, event log, security and hardware health, each with a history graph.
- Alerts per check by email, SMS and on the dashboard.
- Tasks (Windows Task Scheduler): daily, weekly, monthly, monthly by weekday, on check failure, manual, run once and onboarding.
- Policies bundle checks, tasks and a patch policy, apply to clients, sites or as server/workstation default, and inherit downwards.

![Checks of a file server](showcase/device-checks.png)
*Checks of a file server*

![Automated tasks](showcase/device-tasks.png)
*Automated tasks*

![Automation manager](showcase/automation-manager.png)
*Automation manager*

<a id="alerts"></a>

## 8. Alerts and notifications

Alerts collect everything that needs attention; notification routes deliver it to the right channel.

- Alert types: availability, check, task, custom, network and agent, in three severities; snooze, resolve and bulk actions.
- Alert templates run a script, a server action or a REST call on failure and on resolve.
- Notification channels: Matrix, Telegram, ntfy, Slack, Microsoft Teams, webhook and email.
- Routes filter by severity and source, with escalation, quiet hours, muting during maintenance and a delivery history.

![Alerts overview](showcase/alerts-overview.png)
*Alerts overview*

![Editing an alert template](showcase/alert-templates.png)
*Editing an alert template*

![Notification channels and routes](showcase/settings-notifications.png)
*Notification channels and routes*

<a id="patches"></a>

## 9. Patch management and app updates

Operating system patches on all three platforms, third-party app updates, and schedules that wake devices to install them.

- Windows Update: scan, approve by severity through policies, install on a schedule or right away, reboot rules.
- Linux and macOS: apt, dnf, yum, zypper, pacman, apk, flatpak, snap, Homebrew, Homebrew casks and softwareupdate.
- Third-party apps through winget (Windows), Homebrew and the Mac App Store (macOS), with an update hour, a limit per run, exclusions and per-site overrides.
- Maintenance & power: maintenance windows, sleep and wake schedules that wake devices, scan, install approved updates and put them back to sleep.

![Windows updates with approvals](showcase/device-patches.png)
*Windows updates with approvals*

![apt updates found by a real scan](showcase/device-patches-linux.png)
*apt updates found by a real scan*

![winget as second source on Windows](showcase/device-patches-winget.png)
*winget as second source on Windows*

![App updates on a Mac](showcase/device-apps-macos.png)
*App updates on a Mac*

![App update settings](showcase/settings-app-updates.png)
*App update settings*

![Maintenance and power schedules](showcase/maintenance-power.png)
*Maintenance and power schedules*

<a id="software"></a>

## 10. Software inventory and packages

See what is installed, remove it, and roll out your own installers.

- Installed software per device with uninstall; Chocolatey installs on Windows.
- Software packages: upload .exe, .msi, .msix/.appx, .pkg, .deb or .rpm and install them on one device or in bulk.
- On Windows a package runs as SYSTEM or as the logged-in user.
- The device checks each file against its SHA-256 and signature before it runs it; uploading needs the 60-minute two-factor unlock.

![Software inventory](showcase/device-software.png)
*Software inventory*

![Package installs and their results](showcase/software-packages.png)
*Package installs and their results*

<a id="security"></a>

## 11. Vulnerabilities, encryption and credentials

Find known vulnerabilities, store recovery keys and local admin passwords encrypted, and notice when an agent goes missing.

- Vulnerabilities: Linux packages against OSV.dev (Debian, Ubuntu, Alpine, Rocky, AlmaLinux, openSUSE), missing Windows updates against Microsoft's security update data, Windows and macOS apps against the NVD.
- Disk encryption: BitLocker recovery keys are collected and stored, FileVault status with key rotation and escrow, LUKS status on Linux.
- Local admin password rotation for Windows, Linux and macOS per site: account, length, rotation interval, rotation after a reveal; the password lives in the vault.
- Vault: credentials and documents for a client, site or device.
- Agent protection: an uninstall code per agent and an optional tamper watch that alerts when an agent disappears without a shutdown, update or uninstall.

![Vulnerabilities across the fleet](showcase/vulnerabilities.png)
*Vulnerabilities across the fleet*

![Vulnerabilities of one device](showcase/device-vulnerabilities.png)
*Vulnerabilities of one device*

![BitLocker state and recovery key](showcase/device-encryption.png)
*BitLocker state and recovery key*

![Vault with the local admin card](showcase/device-vault.png)
*Vault with the local admin card*

![Local admin rotation policies](showcase/settings-local-admin.png)
*Local admin rotation policies*

![Agent protection](showcase/settings-agent-protection.png)
*Agent protection*

<a id="assets"></a>

## 12. Assets and licenses

Track what you own and what you have paid for.

- Per device: asset tag, vendor, purchase date and price, warranty end; warranty lookup for Dell (TechDirect) and Lenovo.
- Software licenses with seats, expiry and the devices that use them; keys are encrypted and shown only after a two-factor code.
- A notification 30 days before a warranty or license ends; licenses over their seat count are marked.

![Licenses](showcase/settings-licenses.png)
*Licenses*

<a id="network"></a>

## 13. Network monitoring, discovery and integrations

Watch devices that cannot run an agent, find what is on the network, and pull VLANs and switch ports from UniFi and OPNsense.

- Agentless monitoring from the server: ping, TCP ports, SNMP v2c/v3 (interface state, printer toner), HTTP(S) with expected status and certificate expiry, DNS with expected addresses; up to 256 devices.
- Network discovery sweeps subnets for open ports and SNMP and matches each address to an agent or a monitored device; from the result you install an agent or start monitoring.
- UniFi and OPNsense sync clients, VLANs, ARP tables, switch ports, access points and SSIDs.

![Network devices](showcase/network-monitoring.png)
*Network devices*

![Network discovery](showcase/network-discovery.png)
*Network discovery*

![UniFi and OPNsense integration](showcase/settings-network.png)
*UniFi and OPNsense integration*

<a id="history"></a>

## 14. Performance, history and timeline

Stored samples and a complete record of what happened on each device.

- Performance tab: CPU, memory and disks from 1 hour up to 30 days.
- Timeline merges history, audit log, debug log, alerts, pending actions, patches, schedules and package installs.
- History of every command and script run with its output; audit log, debug log and pending actions under Logs.

![Performance over 24 hours](showcase/device-performance.png)
*Performance over 24 hours*

![Timeline](showcase/device-timeline.png)
*Timeline*

![History of the real agent](showcase/device-history.png)
*History of the real agent*

<a id="access"></a>

## 15. Groups, tags and roles

Organise devices and decide who may do what.

- Coloured tags and device groups, static or dynamic; dynamic groups use all/any rules on status, software, version and custom fields.
- Groups and tags filter the device list and target bulk actions.
- Roles with 88 permission flags and limits to chosen clients and sites; API keys and user sessions.

![Device groups](showcase/device-groups.png)
*Device groups*

![New role](showcase/roles.png)
*New role*

<a id="agents"></a>

## 16. Agents

Installers for every platform, built and optionally signed on your own server.

- Windows, Linux and macOS; 64-bit, 32-bit and ARM; standard EXE or PowerShell on Windows; installer tokens with an expiry.
- Deployment links per client and site, automatic agent updates and recovery.
- Self-heal: a watchdog restarts the agent and restores its binary when it was changed or removed.
- Branding (product name, publisher, service names) is built into the agents.

![Add an agent](showcase/install-agent.png)
*Add an agent*

<a id="reporting"></a>

## 17. Reporting

Report templates in Markdown or HTML with data queries, run on demand or on a schedule.

- Base templates, report assets and reusable data queries.
- Schedules email reports as PDF, HTML or text; every run is kept in the run history.

![Report template](showcase/reporting.png)
*Report template*

<a id="branding"></a>

## 18. Branding, RustDesk and dark mode

Put your own name and logo on the dashboard and the agents. Branding does not change the license: a commercial offering to others that competes with the software is a Competing Use under LICENSE.md, which alone is binding.

- Product name, company name, support URL, logo and favicon, shown on the sign-in page, in the header and in the agents.
- Self-hosted RustDesk server with optional automatic server and client updates.
- Light and dark mode per user.

![Branding](showcase/settings-branding.png)
*Branding*

![RustDesk](showcase/settings-rustdesk.png)
*RustDesk*

![Dark mode](showcase/devices-dark.png)
*Dark mode*
