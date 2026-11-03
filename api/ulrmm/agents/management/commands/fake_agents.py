# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

import json
import random
import string
import uuid
from pathlib import Path

from django.conf import settings
from django.core.management import call_command
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone as djangotime

from agents.models import Agent, AgentHistory
from automation.models import Policy
from autotasks.models import AutomatedTask, TaskResult
from checks.models import Check, CheckHistory, CheckResult
from clients.models import Client, Site
from core.models import CoreSettings
from logs.models import AuditLog
from logs.models import PendingAction
from metrics.models import AgentState, Sample
from metrics.state import clean_state, series
from metrics.tasks import disk_usage
from scripts.models import Script
from software import sdio
from software.drivers import clean_drivers
from software.catalog import search_keys
from software.models import (
    DriverCatalog,
    InstalledDrivers,
    InstalledSoftware,
    SdioCatalog,
    SdioIndex,
    WingetCatalog,
)
from ulrmm import sample_data
from ulrmm.constants import AgentHistoryType, AgentMonType, AgentPlat, AlertSeverity
from ulrmm.constants import CheckStatus, CheckType, GoArch, MetricOp, PAAction
from ulrmm.constants import EvtLogFailWhen, EvtLogNames, EvtLogTypes
from ulrmm.constants import ScriptShell, TaskStatus, TaskType
from winupdate.models import DRIVERS_CATEGORY, WinUpdate, WinUpdatePolicy

AGENT_COUNT = 250
CLIENTS = {
    "Northwind Traders": ("Head Office", "Warehouse", "Branch East"),
    "Contoso Clinic": ("Main Building", "Lab", "Reception"),
    "Fabrikam Studio": ("Studio", "Render Farm", "Remote"),
    "Litware Legal": ("Downtown", "Archive", "Home Office"),
    "Adatum Logistics": ("Depot North", "Depot South", "Dispatch"),
    "Tailspin Schools": ("Campus A", "Campus B", "Admin"),
}
WINDOWS_OS = (
    "Windows 10 Pro, 64 bit (build 19045.4291)",
    "Windows 11 Pro, 64 bit (build 22631.3447)",
    "Windows Server 2022 Standard, 64 bit (build 20348.2402)",
    "Windows Server 2019 Standard, 64 bit (build 17763.5696)",
)
LINUX_OS = (
    ("Debian 12.5 x86_64 6.1.0-18-amd64", GoArch.AMD64, "wmi_deb", "disks_linux_deb"),
    ("Raspbian 12 aarch64 6.6.20+rpt-rpi-v8", GoArch.ARM64, "wmi_pi", "disks_linux_pi"),
)
MAC_OS = "macOS 14.4.1 arm64"
# a day of state pushes every 5 minutes for every STATE_EVERY-th agent
STATE_EVERY = 5
STATE_SAMPLES = 288

# device, class, provider, manufacturer, version, date, inf
DEMO_DRIVERS = (
    (
        "Intel(R) Ethernet Connection I219-LM",
        "Net",
        "Intel",
        "Intel",
        "12.19.2.45",
        "2023-03-14",
        "oem12.inf",
    ),
    (
        "NVIDIA RTX A2000",
        "Display",
        "NVIDIA",
        "NVIDIA",
        "31.0.15.3699",
        "2023-08-21",
        "oem31.inf",
    ),
    (
        "Realtek High Definition Audio",
        "MEDIA",
        "Realtek Semiconductor Corp.",
        "Realtek",
        "6.0.9235.1",
        "2021-09-02",
        "oem7.inf",
    ),
    (
        "Intel(R) Chipset SATA/PCIe RST Premium Controller",
        "SCSIAdapter",
        "Intel Corporation",
        "Intel Corporation",
        "18.7.6.1010",
        "2022-05-30",
        "oem4.inf",
    ),
    (
        "HP Universal Printing PCL 6",
        "Printer",
        "HP",
        "HP",
        "61.250.1.24832",
        "2021-10-28",
        "oem55.inf",
    ),
    (
        "Standard NVM Express Controller",
        "SCSIAdapter",
        "Microsoft",
        "Standard NVM Express Controller",
        "10.0.19041.3636",
        "2006-06-21",
        "stornvme.inf",
    ),
    (
        "Disk drive",
        "DiskDrive",
        "Microsoft",
        "(Standard disk drives)",
        "10.0.19041.1",
        "2006-06-21",
        "disk.inf",
    ),
    (
        "HID Keyboard Device",
        "Keyboard",
        "Microsoft",
        "(Standard keyboards)",
        "10.0.19041.1",
        "2006-06-21",
        "keyboard.inf",
    ),
)
DEMO_PROBLEMS = (
    ("PCI Simple Communications Controller", "Unknown", 28),
    ("Base System Device", "Unknown", 28),
)
# pending driver updates the WUA scan offers when drivers are asked for
DEMO_DRIVER_UPDATES = (
    "Intel - Net - 12.19.2.60",
    "NVIDIA - Display - 31.0.15.5222",
)

# id|name|latest version, a slice of the winget index
DEMO_WINGET = """7zip.7zip|7-Zip|26.04
Adobe.Acrobat.Reader.64-bit|Adobe Acrobat Reader DC (64-bit)|25.001.20756
AgileBits.1Password|1Password|8.11.16
Audacity.Audacity|Audacity|3.7.5
BlenderFoundation.Blender|Blender|4.5.3
Brave.Brave|Brave|1.83.118
Canonical.Ubuntu.2404|Ubuntu 24.04 LTS|2404.1.68.0
CodecGuide.K-LiteCodecPack.Standard|K-Lite Codec Pack Standard|19.1.5
Discord.Discord|Discord|1.0.9212
Docker.DockerDesktop|Docker Desktop|4.48.0
Dropbox.Dropbox|Dropbox|234.4.5428
Git.Git|Git|2.51.1
GIMP.GIMP.3|GIMP|3.0.6
Google.Chrome|Google Chrome|141.0.7390.108
Google.GoogleDrive|Google Drive|113.0.1.0
Greenshot.Greenshot|Greenshot|1.3.301
IrfanSkiljan.IrfanView|IrfanView|4.73
JAMSoftware.TreeSize.Free|TreeSize Free|4.7.3
KeePassXCTeam.KeePassXC|KeePassXC|2.7.10
LibreOffice.LibreOffice|LibreOffice|25.8.2.2
Microsoft.Edge|Microsoft Edge|141.0.3537.85
Microsoft.Office|Microsoft 365 Apps for enterprise|16.0.19231.20156
Microsoft.PowerShell|PowerShell|7.5.3.0
Microsoft.PowerToys|PowerToys|0.95.1
Microsoft.Teams|Microsoft Teams|25275.2601.4002.2815
Microsoft.VCRedist.2015+.x64|Microsoft Visual C++ 2015-2022 Redistributable (x64)|14.44.35211.0
Microsoft.VisualStudioCode|Microsoft Visual Studio Code|1.105.1
Microsoft.WindowsTerminal|Windows Terminal|1.23.12811.0
Mozilla.Firefox|Mozilla Firefox (en-US)|157.0.1
Mozilla.Thunderbird|Mozilla Thunderbird (en-US)|144.0.1
Notepad++.Notepad++|Notepad++|8.8.6
OBSProject.OBSStudio|OBS Studio|32.0.1
OpenJS.NodeJS.LTS|Node.js LTS|22.21.0
Oracle.JavaRuntimeEnvironment|Java 8|8.0.4610.11
PDFsam.PDFsam|PDFsam Basic|5.3.2
Postman.Postman|Postman|11.67.4
PuTTY.PuTTY|PuTTY|0.83.0.0
Python.Python.3.13|Python 3.13|3.13.9
RARLab.WinRAR|WinRAR|7.13.0
Rufus.Rufus|Rufus|4.11.2285
ShareX.ShareX|ShareX|18.0.1
SlackTechnologies.Slack|Slack|4.46.101
TeamViewer.TeamViewer|TeamViewer|15.70.4
TheDocumentFoundation.LibreOffice|LibreOffice|25.8.2.2
Valve.Steam|Steam|2.10.91.91
VideoLAN.VLC|VLC media player|3.0.21
WinMerge.WinMerge|WinMerge|2.16.52
WinSCP.WinSCP|WinSCP|6.5.4
WiresharkFoundation.Wireshark|Wireshark|4.6.0
Zoom.Zoom|Zoom Workplace|6.6.2.20541"""
DEMO_DEVICE = "PCI\\VEN_8086&DEV_{:04X}\\3&11583659&0&FE"
DEMO_PRODUCTS = (
    "Windows 10, Vibranium and later, Servicing Drivers, "
    "Windows 11 Client, version 22H2 and later, Servicing Drivers, "
    "Windows - Server, version 21H2 and later, Servicing Drivers"
)


def _random_id(length: int = 40) -> str:
    return "".join(random.choices(string.ascii_letters, k=length))


def _test_data(name: str):
    with open(Path(settings.BASE_DIR) / "ulrmm" / "test_data" / name) as fh:
        return json.load(fh)


class Command(BaseCommand):
    help = "Replace the database contents with demo agents. Development only."

    def handle(self, *args, **kwargs):
        # it wipes agents, clients, scripts, policies and the audit log
        if not settings.DEBUG:
            raise CommandError(
                "fake_agents deletes the existing data and only runs with DEBUG on."
            )

        self.stdout.write("Removing existing data...")
        wiped = (Agent, Client, Check, AutomatedTask, CheckHistory, Policy, Script)
        for model in wiped + (AuditLog, PendingAction):
            model.objects.all().delete()

        for seed in (
            "load_community_scripts",
            "initial_db_setup",
            "load_chocos",
            "create_installer_user",
        ):
            call_command(seed)
        self._catalogs()

        sites = self._clients()
        self._policies()
        scripts = self._scripts()

        wmi = [_test_data(f"wmi{i}.json") for i in (1, 2, 3)]
        services = _test_data("winsvcs.json")
        software = [_test_data("software1.json"), _test_data("software2.json")]
        updates = list(_test_data("winupdates.json")["samplecomputer"].values())

        for n in range(AGENT_COUNT):
            agent = self._agent(n, random.choice(sites), wmi, services)
            self._history(agent, scripts)
            if n % STATE_EVERY == 0:
                self._state(agent, with_checks=n % (STATE_EVERY * 4) == 0)
            if agent.plat != AgentPlat.WINDOWS:
                continue
            InstalledSoftware.objects.create(
                agent=agent, software=random.choice(software)
            )
            self._updates(agent, updates)
            self._drivers(agent, problems=n % 4 == 0)
            if n % 10 == 0:
                self._checks(agent, scripts[0])
                self._task(agent, scripts[0])
            if n % 17 == 0:
                self._scheduled_reboot(agent)

        self.stdout.write(self.style.SUCCESS(f"Created {AGENT_COUNT} demo agents"))

    def _catalogs(self) -> None:
        WingetCatalog.objects.update_or_create(
            pk=1,
            defaults={
                "packages": [line.split("|") for line in DEMO_WINGET.splitlines()],
                "checked": djangotime.now(),
                "updated": djangotime.now(),
                "error": "",
            },
        )
        # the Ethernet driver has a newer catalog entry, the display driver
        # is current, the other devices have none
        DriverCatalog.objects.all().delete()
        for i, (_, _, _, _, version, date, _) in enumerate(DEMO_DRIVERS):
            entries = []
            if i == 0:
                entries = [
                    {
                        "update_id": "ffe0d3f3-52b3-4e26-b9d6-13b5e77bd11d",
                        "title": "Intel Net Driver Update (12.19.2.66)",
                        "products": DEMO_PRODUCTS,
                        "classification": "Drivers (Networking)",
                        "date": "2025-11-15",
                        "version": "12.19.2.66",
                        "size": 286663,
                    }
                ]
            elif i == 1:
                entries = [
                    {
                        "update_id": "2b0d6b3e-6f35-4c47-9a4e-5a1f0c6d7e21",
                        "title": f"NVIDIA - Display - {version}",
                        "products": DEMO_PRODUCTS,
                        "classification": "Drivers (Video)",
                        "date": date,
                        "version": version,
                        "size": 612345678,
                    }
                ]
            for key in search_keys(DEMO_DEVICE.format(i)):
                DriverCatalog.objects.create(
                    hwid=key, checked=djangotime.now(), entries=entries
                )
        # SDIO: a newer Ethernet driver in a pack the mirror serves, a newer
        # display driver only in the BitTorrent swarm
        SdioIndex.objects.update_or_create(
            pk=1,
            defaults={
                "torrent_time": int(djangotime.now().timestamp()) - 86400,
                "checked": djangotime.now(),
                "updated": djangotime.now(),
                "error": "",
                "files": 111,
                "http_packs": ["DP_Net_SDIO01_26103.7z"],
            },
        )
        SdioCatalog.objects.all().delete()
        packs = {0: ("DP_Net_SDIO01_26103.7z", 412_345_678), 1: ("DP_Videos_1.7z", 1)}
        for i, (device, _, provider, _, version, _, _) in enumerate(DEMO_DRIVERS):
            entries = []
            if i in packs:
                pack, size = packs[i]
                entries = [
                    {
                        "hwid": sdio.device_keys(DEMO_DEVICE.format(i))[-1],
                        "pos": 0,
                        "folder": f"demo/allx64/{device.split()[0].lower()}_1/",
                        "inf": "demo.inf",
                        "version": f"{version}.1",
                        "date": "2026-09-01",
                        "provider": provider,
                        "desc": device,
                        "decor": "ntamd64",
                        "alts": [""],
                        "cats": {"amd64": "2:10.0", "x86": "2:10.0"},
                        "pack": pack,
                        "pack_size": size,
                    }
                ]
            for key in sdio.device_keys(DEMO_DEVICE.format(i)):
                SdioCatalog.objects.create(
                    hwid=key, checked=djangotime.now(), entries=entries
                )

    def _clients(self) -> list:
        sites = []
        for client_name, site_names in CLIENTS.items():
            client = Client.objects.create(name=client_name)
            sites += [Site.objects.create(client=client, name=n) for n in site_names]
        return sites

    def _policies(self) -> None:
        servers = Policy.objects.create(name="Demo Servers", active=True)
        workstations = Policy.objects.create(name="Demo Workstations", active=True)
        for policy in (servers, workstations):
            WinUpdatePolicy.objects.create(
                policy=policy, critical="approve", important="approve"
            )
        core = CoreSettings.objects.first()
        core.server_policy = servers
        core.workstation_policy = workstations
        core.save(update_fields=["server_policy", "workstation_policy"])

    def _scripts(self) -> list:
        demo = (
            ("Clear print spooler", ScriptShell.CMD, sample_data.clear_print_spool_bat),
            ("Restart NLA", ScriptShell.POWERSHELL, sample_data.restart_nla_ps1),
            ("Show temp dir", ScriptShell.PYTHON, sample_data.show_temp_dir_py),
        )
        return [
            Script.objects.create(name=name, shell=shell, script_body=body)
            for name, shell, body in demo
        ]

    def _agent(self, n: int, site, wmi, services) -> Agent:
        now = djangotime.now()
        # most are online, some offline or overdue
        seen = now - djangotime.timedelta(minutes=random.choice((0, 0, 0, 1, 8, 90)))
        fields = {
            "site": site,
            "agent_id": _random_id(),
            "agent_ident": settings.AGENT_SVC_NAME,
            "version": settings.LATEST_AGENT_VER,
            "hostname": f"DEMO-{n:04d}",
            "monitoring_type": random.choice(AgentMonType.values),
            "last_seen": seen,
            "boot_time": (
                now - djangotime.timedelta(days=random.randint(0, 30))
            ).timestamp(),
            "public_ip": f"203.0.113.{random.randint(1, 254)}",
            "total_ram": random.choice((8, 16, 32, 64)),
            "logged_in_username": random.choice(("None", "jdoe", "asmith")),
            "needs_reboot": random.random() < 0.1,
        }

        roll = random.random()
        if roll < 0.7:
            fields.update(
                plat=AgentPlat.WINDOWS,
                goarch=GoArch.AMD64,
                operating_system=random.choice(WINDOWS_OS),
                wmi_detail=random.choice(wmi),
                services=services,
                disks=random.choice(sample_data.disks),
            )
        elif roll < 0.9:
            os_name, goarch, wmi_name, disks_name = random.choice(LINUX_OS)
            fields.update(
                plat=AgentPlat.LINUX,
                goarch=goarch,
                operating_system=os_name,
                wmi_detail=getattr(sample_data, wmi_name),
                disks=getattr(sample_data, disks_name),
            )
        else:
            fields.update(
                plat=AgentPlat.DARWIN,
                goarch=GoArch.ARM64,
                operating_system=MAC_OS,
                wmi_detail=sample_data.wmi_mac,
                disks=sample_data.disks_mac,
            )

        agent = Agent.objects.create(**fields)
        if agent.plat == AgentPlat.WINDOWS:
            WinUpdatePolicy.objects.create(agent=agent)
        return agent

    def _history(self, agent: Agent, scripts: list) -> None:
        AgentHistory.objects.create(
            agent=agent,
            type=AgentHistoryType.CMD_RUN,
            command="ipconfig /all" if agent.plat == AgentPlat.WINDOWS else "ip a",
            username="demo",
            results="ok",
        )
        script = random.choice(scripts)
        AgentHistory.objects.create(
            agent=agent,
            type=AgentHistoryType.SCRIPT_RUN,
            script=script,
            username="demo",
            script_results={
                "id": 0,
                "stdout": sample_data.temp_dir_stdout,
                "stderr": "",
                "retcode": 0,
                "execution_time": "1.0412",
            },
        )

    def _updates(self, agent: Agent, updates: list) -> None:
        WinUpdate.objects.bulk_create(
            WinUpdate(
                agent=agent,
                guid=u["guid"],
                kb=f"KB{u['KBs'][0]}" if u.get("KBs") else None,
                title=u["Title"],
                installed=u["Installed"],
                downloaded=u["Downloaded"],
                description=u["Description"],
                severity=u.get("Severity") or "",
            )
            for u in random.sample(updates, k=min(len(updates), 6))
        )

    def _drivers(self, agent: Agent, problems: bool) -> None:
        body = {
            "v": 1,
            "ts": int(djangotime.now().timestamp()),
            "drivers": [
                {
                    "device": device,
                    "class": cls,
                    "provider": provider,
                    "manufacturer": manufacturer,
                    "version": version,
                    "date": date,
                    "inf": inf,
                    "signed": True,
                    "device_id": DEMO_DEVICE.format(i),
                }
                for i, (
                    device,
                    cls,
                    provider,
                    manufacturer,
                    version,
                    date,
                    inf,
                ) in enumerate(DEMO_DRIVERS)
            ],
            "problems": [
                {
                    "name": name,
                    "device_id": f"PCI\\VEN_8086&DEV_A0{i:02X}\\3&11583659&0&A0",
                    "class": cls,
                    "code": code,
                }
                for i, (name, cls, code) in enumerate(DEMO_PROBLEMS if problems else ())
            ],
            "errors": [],
        }
        InstalledDrivers.objects.create(
            agent=agent, received=djangotime.now(), data=clean_drivers(body)
        )
        WinUpdate.objects.bulk_create(
            WinUpdate(
                agent=agent,
                guid=str(uuid.uuid4()),
                kb=None,
                title=title,
                installed=False,
                downloaded=False,
                description=f"{title.split(' - ')[0]} driver update",
                severity="",
                categories=["Drivers"],
                category_ids=[DRIVERS_CATEGORY],
                is_driver=True,
            )
            for title in DEMO_DRIVER_UPDATES
        )

    def _checks(self, agent: Agent, script) -> None:
        now = djangotime.now()
        specs = {
            CheckType.DISK_SPACE: {
                "disk": "C:",
                "warning_threshold": 25,
                "error_threshold": 10,
            },
            CheckType.PING: {"ip": "10.42.0.1"},
            CheckType.CPU_LOAD: {"warning_threshold": 70, "error_threshold": 90},
            CheckType.MEMORY: {"warning_threshold": 70, "error_threshold": 90},
            CheckType.WINSVC: {
                "svc_name": "Spooler",
                "svc_display_name": "Print Spooler",
            },
            CheckType.SCRIPT: {"script": script, "timeout": 90},
            CheckType.EVENT_LOG: {
                "log_name": EvtLogNames.APPLICATION,
                "event_id": 1001,
                "event_type": EvtLogTypes.ERROR,
                "fail_when": EvtLogFailWhen.CONTAINS,
                "search_last_days": 1,
            },
            CheckType.SECURITY: {},
            CheckType.HW_HEALTH: {},
        }
        for check_type, extra in specs.items():
            check = Check.objects.create(
                agent=agent,
                check_type=check_type,
                name=check_type.label,
                alert_severity=AlertSeverity.WARNING,
                **extra,
            )
            failing = check_type == CheckType.PING and random.random() < 0.5
            CheckResult.objects.create(
                assigned_check=check,
                agent=agent,
                status=CheckStatus.FAILING if failing else CheckStatus.PASSING,
                alert_severity=AlertSeverity.WARNING,
                last_run=now,
                more_info=(
                    sample_data.ping_fail_output
                    if failing
                    else (
                        sample_data.ping_success_output
                        if check_type == CheckType.PING
                        else ""
                    )
                ),
            )
            CheckHistory.objects.bulk_create(
                CheckHistory(
                    check_id=check.pk,
                    agent_id=agent.agent_id,
                    y=random.randint(0, 100),
                    results="ok",
                )
                for _ in range(5)
            )

    def _state_doc(self, agent: Agent, step: int) -> dict:
        wave = (step % 48) / 48
        linux = agent.plat == AgentPlat.LINUX
        doc = {
            "v": 1,
            "ts": int(djangotime.now().timestamp()),
            "dt": 300.0,
            "perf": {
                "cpu_pct": round(10 + 50 * wave + random.random() * 10, 1),
                "mem_total": agent.total_ram * 1024**3,
                "mem_used": int(agent.total_ram * 1024**3 * (0.4 + 0.2 * wave)),
                "swap_pct": 3.5,
            },
            "net": {
                "ifaces": [
                    {
                        "name": "eth0" if linux else "Ethernet",
                        "kind": "ether",
                        "state": "up",
                        "speed_mbps": 1000,
                        "duplex": "full",
                        "mac": "52:54:00:12:34:56",
                        "mtu": 1500,
                        "addrs": ["10.42.0.20/24"],
                        "rx_bytes": 9_000_000_000 + step * 4_000_000,
                        "tx_bytes": 2_000_000_000 + step * 1_000_000,
                        "rx_packets": 7_000_000,
                        "tx_packets": 3_000_000,
                        "rx_errors": 0,
                        "tx_errors": 0,
                        "rx_drops": 12,
                        "tx_drops": 0,
                        "rate": {
                            "rx_bps": round(800_000 * (1 + wave), 1),
                            "tx_bps": round(150_000 * (1 + wave), 1),
                            "rx_pps": 600.0,
                            "tx_pps": 220.0,
                            "err_ps": 0.0,
                            "drop_ps": 0.01,
                        },
                    }
                ]
            },
        }
        if agent.plat == AgentPlat.WINDOWS:
            return doc
        doc["perf"]["load"] = [0.4 + wave, 0.5, 0.45]
        mounts = [
            {
                "mount": "/",
                "device": "/dev/sda1",
                "fs": "ext4",
                "ro": False,
                "stale": False,
                "size": 100 * 1024**3,
                "used": 45 * 1024**3,
                "used_pct": 45.0 + wave,
                "inode_pct": 12.0,
            },
            {
                "mount": "/mnt/backup",
                "device": "nas:/backup",
                "fs": "nfs4",
                "ro": True,
                "stale": False,
                "size": 2 * 1024**4,
                "used": 1024**4,
                "used_pct": 50.0,
                "inode_pct": None,
            },
        ]
        doc["system"] = {"mounts": mounts}
        if not linux:
            doc["system"]["manager"] = "launchd"
            return doc
        doc["system"].update(
            {
                "manager": "systemd",
                "units_total": 212,
                "units_failed": 1,
                "units": [
                    {
                        "name": "backup-sync.service",
                        "active": "failed",
                        "sub": "failed",
                        "enabled": True,
                        "description": "Nightly backup sync",
                    },
                    {
                        "name": "apt-daily.service",
                        "active": "activating",
                        "sub": "start",
                        "enabled": False,
                        "description": "Daily apt download activities",
                    },
                ],
                "time": {
                    "synced": True,
                    "source": "chrony",
                    "server": "pool.ntp.org",
                    "offset_ms": round(0.3 + wave, 3),
                },
                "raid": [
                    {
                        "kind": "md",
                        "name": "md0",
                        "level": "raid1",
                        "state": "clean",
                        "health": "ok",
                        "devices": 2,
                        "failed": 0,
                        "sync_pct": None,
                    }
                ],
                "sensors": [
                    {
                        "kind": "temp",
                        "source": "hwmon",
                        "name": "coretemp Package id 0",
                        "value": round(45 + 10 * wave, 1),
                        "unit": "C",
                        "warn": 80.0,
                        "crit": 100.0,
                        "status": "ok",
                    }
                ],
            }
        )
        doc["containers"] = {
            "sources": {"docker": "ok"},
            "items": [
                {
                    "kind": "docker",
                    "id": "4f1c2b3a9d8e",
                    "name": "web",
                    "image": "nginx:1.27",
                    "state": "running",
                    "status": "Up 3 days",
                    "restarts": 0,
                    "cpu_pct": round(2 + 5 * wave, 2),
                    "mem_used": 48 * 1024**2,
                    "mem_limit": 512 * 1024**2,
                    "net_rx": 1_200_000,
                    "net_tx": 9_400_000,
                    "uptime": 259200,
                },
                {
                    "kind": "docker",
                    "id": "9a8b7c6d5e4f",
                    "name": "worker",
                    "image": "python:3.12-slim",
                    "state": "exited",
                    "status": "Exited (1) 2 hours ago",
                    "restarts": 4,
                },
            ],
            "cluster": None,
        }
        return doc

    def _state(self, agent: Agent, with_checks: bool) -> None:
        now = djangotime.now()
        disks = disk_usage(agent.disks)
        docs = [clean_state(self._state_doc(agent, n)) for n in range(STATE_SAMPLES)]
        AgentState.objects.create(agent=agent, received=now, agent_ts=now, data=docs[0])
        Sample.objects.bulk_create(
            Sample(
                agent=agent,
                ts=now - djangotime.timedelta(minutes=5 * n),
                cpu=doc["perf"]["cpu_pct"],
                mem_total=doc["perf"]["mem_total"] // 1024**2,
                mem_used=doc["perf"]["mem_used"] // 1024**2,
                disks=disks,
                values=series(doc),
            )
            for n, doc in enumerate(docs)
        )
        if not with_checks:
            return

        specs = [
            {
                "check_type": CheckType.METRIC,
                "metric": "cpu.pct",
                "metric_warning": 50.0,
                "metric_error": 80.0,
                "metric_samples": 3,
            },
        ]
        if agent.plat == AgentPlat.LINUX:
            specs += [
                {"check_type": CheckType.SYSTEMD, "svc_name": "backup-sync.service"},
                {
                    "check_type": CheckType.CONTAINER,
                    "container": "web",
                    "container_kind": "docker",
                },
                {
                    "check_type": CheckType.METRIC,
                    "metric": "temp.c",
                    "metric_labels": {"sensor": "*"},
                    "metric_op": MetricOp.ABOVE,
                    "metric_warning": 70.0,
                    "metric_error": 90.0,
                },
            ]
        for spec in specs:
            check = Check.objects.create(
                agent=agent, alert_severity=AlertSeverity.WARNING, **spec
            )
            failing = spec["check_type"] == CheckType.SYSTEMD
            CheckResult.objects.create(
                assigned_check=check,
                agent=agent,
                status=CheckStatus.FAILING if failing else CheckStatus.PASSING,
                alert_severity=AlertSeverity.WARNING,
                last_run=now,
                more_info="failed/failed, restarts 3" if failing else "",
            )

    def _task(self, agent: Agent, script) -> None:
        task = AutomatedTask.objects.create(
            agent=agent,
            name="Clear print spooler",
            task_type=TaskType.DAILY,
            daily_interval=1,
            run_time_date=djangotime.now(),
            actions=[
                {
                    "type": "script",
                    "script": script.pk,
                    "name": script.name,
                    "env_vars": [],
                    "script_args": [],
                    "timeout": 90,
                }
            ],
        )
        TaskResult.objects.create(
            agent=agent,
            task=task,
            retcode=0,
            stdout=sample_data.spooler_stdout,
            stderr="",
            execution_time="2.1300",
            last_run=djangotime.now(),
            status=TaskStatus.PASSING,
        )

    def _scheduled_reboot(self, agent: Agent) -> None:
        when = djangotime.now() + djangotime.timedelta(days=random.randint(1, 7))
        PendingAction.objects.create(
            agent=agent,
            action_type=PAAction.SCHED_REBOOT,
            details={
                "taskname": f"{settings.AGENT_TASK_PREFIX}SchedReboot_{_random_id(10)}",
                "time": str(when.replace(tzinfo=None, second=0, microsecond=0)),
            },
        )
