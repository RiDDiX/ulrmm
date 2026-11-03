# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""Sample payloads for the ``fake_agents`` dev command and the baker recipes.

Everything here is invented demo data: disk layouts, hardware inventories,
helper scripts and captured-looking command output. No test asserts the
contents, only that the names import and the shapes fit the consumers.
"""

# --- disk layouts ----------------------------------------------------------
# each disk dict: free/used/total/device/fstype are strings, percent an int

disks = [
    [
        {
            "free": "180.4 GB",
            "used": "69.6 GB",
            "total": "250.0 GB",
            "device": "C:",
            "fstype": "NTFS",
            "percent": 28,
        }
    ],
    [
        {
            "free": "92.1 GB",
            "used": "407.9 GB",
            "total": "500.0 GB",
            "device": "C:",
            "fstype": "NTFS",
            "percent": 82,
        },
        {
            "free": "1.4 TB",
            "used": "0.6 TB",
            "total": "2.0 TB",
            "device": "D:",
            "fstype": "NTFS",
            "percent": 30,
        },
    ],
    [
        {
            "free": "40.2 GB",
            "used": "87.8 GB",
            "total": "128.0 GB",
            "device": "C:",
            "fstype": "NTFS",
            "percent": 69,
        },
        {
            "free": "512.0 GB",
            "used": "488.0 GB",
            "total": "1.0 TB",
            "device": "E:",
            "fstype": "ReFS",
            "percent": 48,
        },
    ],
    [
        {
            "free": "11.9 GB",
            "used": "100.1 GB",
            "total": "112.0 GB",
            "device": "C:",
            "fstype": "NTFS",
            "percent": 89,
        },
        {
            "free": "210.0 GB",
            "used": "46.0 GB",
            "total": "256.0 GB",
            "device": "D:",
            "fstype": "NTFS",
            "percent": 18,
        },
        {
            "free": "3.1 TB",
            "used": "0.9 TB",
            "total": "4.0 TB",
            "device": "F:",
            "fstype": "NTFS",
            "percent": 22,
        },
    ],
]

disks_linux_pi = [
    {
        "free": "22.8 GB",
        "used": "6.2 GB",
        "total": "29.0 GB",
        "device": "/dev/mmcblk0p2",
        "fstype": "ext4",
        "percent": 21,
    },
    {
        "free": "198.0 MB",
        "used": "58.0 MB",
        "total": "256.0 MB",
        "device": "/dev/mmcblk0p1",
        "fstype": "vfat",
        "percent": 23,
    },
]

disks_linux_deb = [
    {
        "free": "63.5 GB",
        "used": "34.5 GB",
        "total": "98.0 GB",
        "device": "/dev/sda1",
        "fstype": "ext4",
        "percent": 35,
    },
    {
        "free": "410.0 GB",
        "used": "90.0 GB",
        "total": "500.0 GB",
        "device": "/dev/sdb1",
        "fstype": "ext4",
        "percent": 18,
    },
]

disks_mac = [
    {
        "free": "308.0 GB",
        "used": "192.0 GB",
        "total": "500.0 GB",
        "device": "/dev/disk3s1",
        "fstype": "apfs",
        "percent": 38,
    },
    {
        "free": "480.0 GB",
        "used": "20.0 GB",
        "total": "500.0 GB",
        "device": "/dev/disk3s5",
        "fstype": "apfs",
        "percent": 4,
    },
    {
        "free": "0.5 GB",
        "used": "0.1 GB",
        "total": "0.6 GB",
        "device": "/dev/disk3s6",
        "fstype": "apfs",
        "percent": 17,
    },
]

# --- hardware inventories (agent.wmi_detail) -------------------------------

wmi_deb = {
    "cpus": ["Intel(R) Xeon(R) E-2336 CPU @ 2.90GHz"],
    "gpus": ["Matrox G200eW3"],
    "disks": ["Samsung SSD 870 500GB", "Seagate ST500DM002 500GB"],
    "local_ips": ["10.42.0.14/24"],
    "make_model": "Dell Inc. PowerEdge R250",
}

wmi_pi = {
    "cpus": ["ARM Cortex-A72 (4 cores)"],
    "gpus": [],
    "disks": ["SanDisk Ultra 32GB microSD"],
    "local_ips": ["10.42.0.51/24"],
    "make_model": "Raspberry Pi 4 Model B Rev 1.4",
}

wmi_mac = {
    "cpus": ["Apple M2"],
    "gpus": ["Apple M2 (10-core GPU)"],
    "disks": ["APPLE SSD AP0512Z 500GB"],
    "local_ips": ["10.42.0.88/24"],
    "make_model": "Apple Mac mini (2023)",
}

# --- scripts ---------------------------------------------------------------

check_network_loc_aware_ps1 = r"""# exits 0 when the active connection is on a domain-authenticated profile
$profiles = Get-NetConnectionProfile
$domain = $profiles | Where-Object { $_.NetworkCategory -eq 'DomainAuthenticated' }
if ($domain) {
    Write-Output "network location awareness: domain profile active"
    exit 0
}
Write-Output "network location awareness: no domain profile, nic is public/private"
exit 1
"""

check_storage_pool_health_ps1 = r"""# fails if any virtual disk is not reporting Healthy
$unhealthy = Get-VirtualDisk | Where-Object { $_.HealthStatus -ne 'Healthy' }
if ($unhealthy) {
    foreach ($disk in $unhealthy) {
        Write-Output ("unhealthy virtual disk: {0} -> {1}" -f $disk.FriendlyName, $disk.HealthStatus)
    }
    exit 1
}
Write-Output "all virtual disks healthy"
exit 0
"""

clear_print_spool_bat = r"""@echo off
rem stop the spooler, clear queued jobs, start it again
net stop spooler
del /Q /F "%systemroot%\System32\spool\PRINTERS\*.*"
net start spooler
echo print spooler cleared
"""

restart_nla_ps1 = r"""# restart Network Location Awareness so the nic re-detects its profile
Restart-Service -Name NlaSvc -Force
Write-Output "restarted NlaSvc"
"""

show_temp_dir_py = r"""import os
import tempfile

temp_dir = tempfile.gettempdir()
entries = []
for name in os.listdir(temp_dir):
    path = os.path.join(temp_dir, name)
    try:
        stat = os.stat(path)
    except OSError:
        continue
    entries.append({"name": name, "size": stat.st_size, "mtime": int(stat.st_mtime)})

print("Total files: {}".format(len(entries)))
print("")
for entry in entries:
    print(entry)
"""

redhat_insights = r"""#!/usr/bin/env bash
# apply a list of advisories, one id per line, from the file given as $1
set -u
advisories="$1"
if [ ! -f "$advisories" ]; then
    echo "advisory file not found: $advisories" >&2
    exit 2
fi

args=()
while read -r advisory; do
    [ -n "$advisory" ] && args+=("--advisory" "$advisory")
done < "$advisories"

yum --assumeno check-update "${args[@]}"
rc=$?
if [ "$rc" -ne 100 ]; then
    echo "nothing to update for the given advisories (check-update returned $rc)" >&2
    exit 1
fi

yum -y update "${args[@]}"
"""

# --- captured-looking command output ---------------------------------------

ping_success_output = """Pinging gateway.example.lan [10.42.0.1] with 32 bytes of data:
Reply from 10.42.0.1: bytes=32 time=1ms TTL=64
Reply from 10.42.0.1: bytes=32 time=1ms TTL=64
Reply from 10.42.0.1: bytes=32 time=2ms TTL=64

Ping statistics for 10.42.0.1:
    Packets: Sent = 3, Received = 3, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 1ms, Maximum = 2ms, Average = 1ms
"""

ping_fail_output = """Pinging offline.example.lan [10.42.0.240] with 32 bytes of data:
Request timed out.
Request timed out.
Request timed out.

Ping statistics for 10.42.0.240:
    Packets: Sent = 3, Received = 0, Lost = 3 (100% loss),
"""

spooler_stdout = """SERVICE_NAME: Spooler
        TYPE               : 110  WIN32_OWN_PROCESS (interactive)
        STATE              : 3  STOP_PENDING
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)

SERVICE_NAME: Spooler
        TYPE               : 110  WIN32_OWN_PROCESS (interactive)
        STATE              : 1  STOPPED

SERVICE_NAME: Spooler
        TYPE               : 110  WIN32_OWN_PROCESS (interactive)
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
"""

temp_dir_stdout = """Total files: 3

{'name': 'build.log', 'size': 20841, 'mtime': 1733312401}
{'name': 'session.lock', 'size': 0, 'mtime': 1733312455}
{'name': 'upload.tmp', 'size': 1048576, 'mtime': 1733312460}
"""
