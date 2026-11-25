# Client system images

Open a device and choose its **Backups** tab (under **More** when the tab strip is full). The **Backups** page in the main navigation shows every device and the backup policies; see [Backups page, policies and runs](#backups-page-policies-and-runs). Deploy the matching server, dashboard and agent builds. Review the agent-reported source, recovery medium, encryption state and prerequisites for each device before applying a backup policy. Each queued point records that configuration. Operators can authorize recovery from the dashboard after loss of the original agent credentials. Build agent version `1.22.11.2026` or later with the usual managed build/signing process; settings acknowledgement, readiness checks, run progress, hooks and cancel need agent `1.24.11.2026` or later. Use `ulrmm-agent -m imaging` on an enrolled device to report inventory immediately and process a waiting job through the same provider and connection as its service.

| Agent and source | Recovery procedure | Validation |
| --- | --- | --- |
| Windows x64 with the native Windows Server Backup feature, supported GPT/UEFI layout and dedicated NTFS staging | Stage the verified WindowsImageBackup catalog, then select its version in WinRE. | [Windows prerequisites and acceptance](CLIENT_IMAGING_WINDOWS.md) |
| Linux x86-64 with a directly partitioned ext4 root and local boot partitions | Clean shutdown, signed/trusted rescue environment with the agent capture command, whole-disk recovery, then boot from the target disk. | [Linux layouts and acceptance](CLIENT_IMAGING_LINUX.md) |
| Intel Mac with an eligible dedicated external APFS Time Machine disk | Reconstruct the selected Time Machine medium. Reinstall via Intel Recovery and migrate in Setup Assistant or Migration Assistant. | [Mac prerequisites and acceptance](CLIENT_IMAGING_MACOS.md) |
| Apple Silicon Mac with an eligible dedicated external APFS Time Machine disk | Reconstruct the external medium, start macOS Recovery from startup options, reinstall and migrate the selected backup. | [Mac prerequisites and acceptance](CLIENT_IMAGING_MACOS.md) |

### Storage and incremental points

The agent reads a consistent provider artifact and splits it into 2 MiB blocks. Before sending each block it submits its SHA-256. The service may reuse a stored block belonging to the same device, destination, network mode, codec and compression level. Gzip compresses new blocks on the sender. Each verified point owns its complete ordered block list, byte length and full-stream SHA-256. The server checks the length and digest of every dependency and the complete stream before marking a point verified. A retry assembles a fresh ordered list and can reuse blocks from the interrupted upload. Restoring an earlier point does not replay later changes. Backup service recovery requires both the PostgreSQL database and the private block storage.

After an agent process stops during upload, five minutes without a committed block make the same point eligible for a new claim. A run of agent `1.24.11.2026` or later that still reports progress keeps its point; when it has reported nothing for its pause limit plus 15 minutes, the run is interrupted and the point can be claimed again. The earlier grant expires when the new claim is issued. Retries rebuild the ordered map from the retained capture and reuse verified stored blocks. Before upload starts, a one-hour claim window allows the native snapshot to finish. Each committed block, and each progress report of a running backup, keeps the claim valid for at least another hour, up to seven days after the claim.

A new job wakes an online agent via the existing NATS envelope. The wake-up carries no capture parameters or secrets. The reporting agent retrieves the authorized job over its enrolled HTTPS connection and also polls every five minutes for requests queued while offline. A separate direction-scoped bearer authorizes data transfer to the configured HTTPS origin. Backup jobs have no operation for downloading or deleting previous points. The recovery operator receives independent short-lived restore access after scope checks and an MFA step-up. Restore access starts with two hours, and each downloaded chunk keeps it valid for at least another hour, up to seven days after issue. The last chunk keeps it valid for 24 hours, which covers writing and reading back the disk before completion is recorded. Capture access slides the same way with each committed chunk. An operator can export one complete verified native artifact with the matching agent binary in recovery mode:

```sh
ulrmm-agent imaging-fetch --url "$transfer_url" --image "$image_id" \
  --target "$target_agent_id" --disk "$approved_disk_id" --output "$new_artifact" \
  --network-mode internal --interface "$wireguard_interface"
```

Supply the one-time-shown grant on standard input. Choose a private staging directory on a filesystem that supports hard links, such as NTFS, ext4 or APFS. The helper downloads into `<output>.<first 16 hex digits of the SHA-256>.partial`, checks its size and SHA-256, reads it back, and publishes it under the new output name. After an interruption, running the same command again continues from that partial file. Follow the platform guide to apply the staged artifact. Download completion records retrieval, while boot, login, restored permissions and re-enrollment require checks on the recovered system. For the installed agent set `ULRMM_IMAGING_INTERFACE` in its service environment for internal-mode jobs. Check platform-specific tunnel support in the guides. Internet-enabled profiles use a direct HTTPS connection with certificate validation.

### Design references and component updates

UrBackup 2.5.38 supports incremental and synthetic full image backups. Its server assembles image backups and tracks their relationships. ULRMM uses the changed-block transfer principle and stores a complete per-point map to support the three native recovery formats. UrBackup remains an architecture reference. Its AGPLv3 backend is not bundled. [Administration manual, sections 6.2 and 8.5](https://www.urbackup.org/administration_manual.html) · [2.5.38 image implementation](https://github.com/uroni/urbackup_backend/blob/c52ff0521d7ac5869cda90d2b053cd770ac4b588/urbackupserver/ImageBackup.cpp) · [License](https://github.com/uroni/urbackup_backend/blob/c52ff0521d7ac5869cda90d2b053cd770ac4b588/COPYING)

Clonezilla Live 3.3.3-37 and Partclone 0.3.54 provide offline imaging; Partclone can copy filesystem-allocated blocks. Clonezilla documents the unmounted-source requirement and absence of incremental imaging. ULRMM keeps its prior whole-disk Linux recovery format for boot sectors and partitions, and puts reuse in the server's block store. These GPL tools are references only. Windows tools and Time Machine are serviced by the OS vendor. The Go providers use the normal ULRMM agent build and update flow. Provision the Linux recovery helper and Windows staging helper from the matching ULRMM server revision. [Clonezilla releases](https://clonezilla.org/downloads.php) · [Clonezilla limitations and license](https://clonezilla.org/) · [Partclone 0.3.54 source](https://github.com/Thomas-Tsai/partclone/tree/0.3.54)

## Server setup

### Standalone server (default)

After `install.sh`, or `update.sh` on an existing server, imaging is ready. No setting needs to be edited. Images go to `/rmmimages` on the ULRMM server. The folder belongs to the service user and has mode `0700`. The server keeps 10 GiB free on that file system (`ULRMM_IMAGING_RESERVE_BYTES`). An upload that would go below that waits for free space. Agents send to the API name over HTTPS, and the API site's nginx already takes these transfers.

In the device's **Backups** tab or a backup policy, set **Transfer network** to **Internet upload allowed**. **ULRMM internal network only** needs the internal listener described below.

To use another disk, mount it at `/rmmimages`, owned by the service user with mode `0700`. Or choose its folder in Global Settings -> **System Images**, see below. `update.sh` creates a missing `/rmmimages`. It never changes an existing folder.

`backup.sh` does not include the images. Back up the folder or the volume together with the database.

### Change the storage folder

Mount points change, so the folder can be changed in Global Settings -> **System Images**. Enter the new folder. The page checks it before anything is saved: absolute path, not a system folder, not `/tmp` or `/var/tmp`, not inside or around the current store, and not a shared parent such as `/mnt` itself, a directory and not a link, owned by the service user, mode `0700`, and empty or an image folder. A folder that holds other files gets the command for a new subfolder instead. A failed check comes with the exact command that fixes it, for example `sudo install -d -m 0700 -o USER -g GROUP /mnt/disk/rmmimages` with the service user filled in. Saving needs a two-factor confirmation and goes to the audit log. API, worker and beat use the new folder without a restart. An empty field goes back to the server default, `ULRMM_IMAGING_ROOT` in `ulrmm/local_settings.py` (`/rmmimages`).

Copy the existing points first: `sudo rsync -a /rmmimages/ /mnt/disk/rmmimages/`, then save. Or mount the same disk at the new place. While points exist, the server accepts a new folder only when it holds the newest stored backup data, so an empty or outdated disk cannot hide the stored points. Run rsync again if backups ran after the copy. If the old folder is gone, for example after a mount point moved, choose the folder that now holds the disk. Every image folder also holds a `.ulrmm-images` file with this server's store id, and the server remembers the file system the store lives on. When the disk is not mounted, or another disk without the newest backups is mounted there, backups and checks wait and the dashboard says so; stored points are not marked failed. A disk that comes back under another device number, or a full copy on a new disk mounted at the same place, is taken over by itself. If only an older copy of the store is left, choose its folder: the page marks it as an older copy, and points whose data it lacks fail when they are checked. Pooled file systems that spread one folder over several disks, such as mergerfs or Unraid user shares, are not supported as a store: a missing member disk looks like lost files there.

If the disk is lost for good, its points cannot come back. Choose an empty folder, for example on the replacement disk, tick **Start a new store and retire the stored points** and save. The option appears only while the current store cannot be read, stored points exist and the folder is empty. A dying disk that is still mounted stays the store: unmount it first. A replacement disk mounted at the old place gets the offer as soon as the page opens; prepare its root with `sudo install -d -m 0700 -o USER -g GROUP <folder>` or the `chown`/`chmod` command the page shows. Every stored point is then marked failed with the reason "The store that held this point was replaced in Global Settings.", open transfers of those points end, the block index is cleared and the folder gets a new store id. The audit log names how many points were retired. The failed points can then be deleted, and the next backups upload in full.

Docker: the path inside the containers stays `/rmmimages`. By default it is the `images` volume, mounted in init, api, celery and celerybeat. For another disk, create the host folder with uid 1000 as owner: `sudo install -d -m 0700 -o 1000 -g 1000 /mnt/disk/rmmimages`. Copy the points from the volume, for example `docker run --rm -v ulrmm_images:/from:ro -v /mnt/disk/rmmimages:/to alpine cp -a /from/. /to/` (the volume prefix is the compose project name). Then set `IMAGING_VOLUME=/mnt/disk/rmmimages` in `.env` and run `docker compose up -d`. Leave the folder in Global Settings on the server default.

### Advanced setup

1. API, Celery worker and Celery beat must use the same configuration. API and worker need the same storage path and service UID. Beat queues pending captures, and the worker verifies images.
2. Your own storage directory must be absolute and outside the document root. Set its owner to the backend service UID and its mode to `0700`. On native installs, `systemctl show rmm -p User --value` reports the service user. In containers, bind the same persistent volume at the configured path in API, worker and beat.
3. Configure the permitted HTTPS origins in `ulrmm/local_settings.py`. Without `ULRMM_IMAGING_PUBLIC_ORIGIN` and `ULRMM_IMAGING_INTERNAL_ORIGIN` the server uses `https://` and the first host name in `ALLOWED_HOSTS`, with `ULRMM_BACKEND_PORT` when set. Set it for another name, or when internal transfers are configured and internet uploads should be allowed too. Enable the internal settings only after verifying the topology below. Ensure both hostnames have valid TLS certificates and are accepted in `ALLOWED_HOSTS`. Restart the affected services.
4. Each backup target is one folder under this root. Global Settings → **System Images** → **Backup targets** lists them; a policy or a device picks its **Backup target**. Backup data can contain all files from the client. Provision capacity and encryption at rest on this server. Retention removes verified points by the rules in [Retention and quotas](#retention-and-quotas). A single verified or failed point can be deleted from the device tab after a two-factor confirmation. Blocks shared between points are freed once no point uses them, at the earliest one day after they were stored. Back up the imaging database records alongside these files. Images of a deleted device can no longer be restored and are removed 30 days after the device is deleted, so keep the device record while its images may be needed. All blocks of a destination share one folder: on ext4 without `large_dir`, keep a destination below about 20 TB of unique data, or use XFS or several destinations. Compression does not encrypt backups. Set `ULRMM_IMAGING_ENCRYPTED_DESTINATIONS` to the folder names on separately verified encrypted storage. The UI labels this as administrator confirmation. Source BitLocker, LUKS or FileVault alone cannot establish encryption of the backup destination.

A setup with its own disk and internal transfers:

```python
ULRMM_IMAGING_ROOT = "/srv/ulrmm-images"
ULRMM_IMAGING_PUBLIC_ORIGIN = "https://api.example.com"
ULRMM_IMAGING_INTERNAL_ORIGIN = "https://images.vpn.example.com"
ULRMM_IMAGING_INTERNAL_CIDRS = ["10.77.0.0/24"]
ULRMM_IMAGING_INTERNAL_STORAGE_CONFIRMED = True
ALLOWED_HOSTS += ["images.vpn.example.com"]
```

### Internal ingress

Use a dedicated HTTPS listener reachable through the managed WireGuard tunnel. Bind its address to the VPN, filter its source peers, and configure the transfer location below in that listener. The API reads the uWSGI variable supplied by this listener. The public listener must omit that variable. If a reverse proxy terminates TLS before this listener and the original tunnel cannot be established, leave internal ingress disabled.

```nginx
location ^~ /imaging/transfers/ {
    allow 10.77.0.0/24;
    deny all;
    client_max_body_size 4m;
    client_body_buffer_size 4m;
    include /etc/nginx/uwsgi_params;
    uwsgi_param ULRMM_IMAGING_INTERNAL_PEER $remote_addr;
    uwsgi_pass ulrmm;
}
```

The recovery tool checks and binds its actual TLS socket to the designated WireGuard interface on each request. It uses the configured origin directly, disables proxy discovery and rejects redirects. The backend also checks the receiving host, secure transport, ingress peer and server storage. Confirm that both the root and destination reside on locally attached storage. A network-backed block device can advertise a local filesystem type. Keep the confirmation disabled for unverified infrastructure and review it after storage changes.

### Permissions

Assign **View System Images**, **Manage System Images** and **Restore System Images** under Roles as appropriate. Manage permits configuration, capture and pairing. Restore checks source and target scope and requires a dashboard session with a current two-factor unlock. All rights are checked per device against the role's client and site scope.

| Action | Needs |
| --- | --- |
| Devices tab of the Backups page, a device's Backups tab, its runs and logs | View, Manage or Restore System Images; the Devices tab lists only devices the role may see |
| Save device settings, **Request backup**, **Check now**, **Cancel run**, protect a point, **Preview retention**, confirm or reject a held change | Manage System Images on the device |
| Remove the protection of a point | Manage System Images and a current two-factor unlock |
| Policies tab, save or delete a policy | Manage System Images. Global, device group and tag policies also need a role without client or site restriction; a client policy needs manage rights on that client, a site policy rights on that site; an assigned policy needs Manage System Images on every device it adds or removes |
| Add, change or remove hooks; create or delete a policy that holds hooks (an empty hooks list counts, it switches inherited hooks off); change the scope, scope object, priority or devices of such a policy or whether its hooks are enforced; confirm a changed hook script; confirm a held change that changes hooks | **Run Script** on every device the setting reaches (for global, client, site, group and tag policies a role with Run Script and without client or site restriction) and a current two-factor unlock |
| See hook arguments and hook output | Run Script on the device; other roles see the number of arguments and "Output hidden" |
| Add, change or delete backup targets | **Edit Global Settings**; the list is shown with View Global Settings or Manage System Images | The recovery media uses an expiring grant for a single image, transfer direction, device UUID and disk ID. Grant secrets are shown once. Keep pairing tokens on protected rescue media, outside the disk being imaged.

For a replacement device's signed site enrollment, the deployment must be valid and the server must have an active installer user. Confirm the old agent credential is blocked before reconnecting a restored system. Retain its device record while its recovery points are needed.

## Backups page, policies and runs

### Where things are

The **Backups** page has two tabs. **Devices** lists each device with its policies, settings state, readiness, last verified point, next backup, stored size, open alerts, current run and held change. The chips filter for stale devices, devices that are not ready, refused settings, pending settings, older agents and held changes; the list refreshes every 30 seconds. **Policies** lists the backup policies by level and opens the policy dialog with **New policy**. Backup targets are kept in Global Settings → **System Images** → **Backup targets**.

A device's **Backups** tab shows each setting with its origin, the settings state, a held change, the readiness checks, the current run, the last 10 runs, the storage used per target and the points. **Assign a backup policy…** opens the dialog for assigned policies, and **Backup policies** opens the Backups page. Saving the device settings keeps the device in its assigned policy.

### Policy levels

Each setting is resolved on its own, from the lowest level to the highest: the built-in defaults, the **Global default** policy, the policy of the device's client, the policy of its site, the device group and tag policies that match the device, its assigned policy, and the device's own settings. A higher level replaces the value of a lower one; a list or an object, such as the schedule, the windows, the retention tiers, the bandwidth limits, the volumes or the hooks, replaces it as a whole. Among device group and tag policies the higher **Priority** (-1000 to 1000) wins, and at equal priority the older policy wins; when two such policies at equal priority set the same field, the field shows which one applies. The Global default always exists and cannot be deleted. A client and a site can each have one policy. In a policy, **Set … at this level** turns a field on; a field that is off inherits from the level below. On the device, **Reset to inherited** takes a device value back on the next save.

A policy can enforce **Backup target**, **Hooks** and **Automatic setup** when it sets them. The lowest level that enforces a field decides it: higher levels and the device keep their values but cannot change it, and a device save of that field is refused with "Enforced by backup policy <name>.". The chip of the field shows the lock.

Policy and device saves apply at once. A change of the device's memberships, from a tag, a device group rule, the members of a dynamic group or a move to another site, applies at once only when the user who made it holds Manage System Images on the device, and also Run Script when the hooks would change; for a dynamic group, the user who last edited its rule counts. Otherwise the device keeps its current settings and the change is held. The device tab lists every setting it moves, and the Devices tab shows it under **Held change**. A user with Manage System Images on the device confirms or rejects it; a change that moves hooks needs Run Script and a two-factor unlock to confirm. While a change is held, nothing applies by itself: later membership changes update the same held change. It is withdrawn when the memberships return to their previous state, and a rejected change is not offered again. A client, site, device group or tag that a backup policy or target names cannot be deleted until they are removed ("Remove the backup policies ... first.").

### Settings state

The agent receives the settings it applies as a versioned document and acknowledges each version. The device tab shows **Synced** with the applied version, **Pending** while the device is offline or has not polled yet, **Refused** with the field and reason when the agent cannot apply a version, and **Older agent** for agents before `1.24.11.2026`. A refused version leaves the previous settings in force, with automatic setup off; the agent checks it again on each poll and applies it once it passes, for example when the WireGuard tunnel of an internal-only setting is up. Schedules, windows, retention, quotas and alerts stay on the server. Hook scripts travel only with a claimed backup. The agent fetches settings and claims backups only over its sealed channel; a device without an active agent identity makes no backup, and its check `agent.sealing` names the reason. An agent that cannot verify the server's sealed answers, for example an agent built for another server, reports the version as **Refused** with the field `sealing` and tries again with a growing wait of up to 6 hours. While it cannot verify the seal it also refuses the server's wake-up; once the cause is gone, the next wake-up (a due backup, **Check now** or saved settings) or a restart of the agent service makes it fetch at once. The device is not ready with that reason until then.

### Schedules

| Schedule | Runs |
| --- | --- |
| Manual only | Only on **Request backup** or an event |
| Daily | At the time in the time zone |
| Every N hours | N hours (1-720) after the last verified point; at once when there is none |
| Calendar | On dates, daily, weekly on weekdays, or monthly on a day of the month or a weekday of a week, with skipped dates and an optional start and end date |
| Cron expression | Five fields, minute hour day month weekday; Sunday is 0, and the day of month and the weekday must both match |

**Event triggers** add a backup when the agent starts or when AC power is connected, if no point is open and the minimum spacing has passed (agent `1.24.11.2026` or later). The time zone is an IANA name; empty uses the device's time zone. A time in the spring daylight-saving gap moves forward, an ambiguous autumn time runs at its first occurrence. **Minimum spacing** (default 60 minutes) is the least time between two points of the device. A skipped occurrence moves the next due time at least the spacing, the interval or 15 minutes ahead, whichever is longest.

A device has at most one open point. A scheduled or event point that no agent has claimed yet is replaced by the next occurrence; while any other point is open the occurrence waits and is tried again after the minimum spacing, at least 15 minutes later. **Missed backups** decides what happens while a device is off: **Run once when the device is back** (default) keeps one waiting point, audits how many missed runs were coalesced into it, and starts it **Catch-up delay** minutes (default 10) after the device is back. **Skip missed runs** queues nothing while the device is offline and audits the skip. **Request backup** returns the open point when there is one ("A backup point is already open."); otherwise its point can be claimed at once, without the catch-up delay. Windows, battery, quota and the run limit apply to every point.

**Backup windows** and **Blackout windows** are weekly ranges in the policy time zone; a range whose end is before its start runs past midnight. Outside an allowed window or inside a blackout a point waits with "Waiting for the backup window.". With **Stop at window end**, an agent warns 10 minutes before the end and ends a run that has not finished uploading as interrupted with "The backup window ended.".

Scheduled and event points run on the authority of the policy whose schedule applies, or of the device schedule, and need no backup operator. When that policy no longer reaches the device, the point fails with "The backup schedule that queued this point no longer applies to this device.". A manual point needs its requester to keep Manage System Images on the device.

### Retention and quotas

Retention works per device and target over verified points. **Keep last** keeps the newest N points (0-365). The **Retention tiers** keep the newest point of each of the last N hours, days, weeks, months and years (0-1000 each), counted in the policy time zone. The newest point, protected points and points with an open restore are always kept; when keep last and every tier are 0, every point is kept. Retention runs after each verified backup and in the regular pass of the server, which removes at most 20 points per minute. A failed point is removed 7 days after it failed when a newer verified point of the same target exists. **Protected** on a verified point keeps it from retention; removing the protection needs a two-factor unlock. **Preview retention** in the device tab shows, for the values in the form, which points are kept by which rule and which the next pass deletes.

**Device quota** limits the stored size of the device on its target, and a target can have a quota of its own. A used-up quota makes new backups wait with "The backup quota of this device is used up." or "The backup target <name> is full." and raises an alert; a quota never deletes a point. **Backups at the same time** on a target (default 5) limits concurrent runs; further points wait with "Waiting: <n> backups already run on target <name>.". A client or site target serves only the devices of that client or site, a policy can only use a target that covers its scope, and the default target is global. The name of a target that points use cannot change, and the default target cannot be deleted.

### Hooks

A hook runs a saved script on the device around a backup: **Before the backup**, **Before the snapshot**, **After the snapshot** or **After the backup, always**. The platform guides say where the snapshot phases fall for each method. Hooks run as the agent service account, root or SYSTEM; a script set to run as the logged-in user fails when nobody is logged in. A script whose platforms exclude the device is skipped. Up to 8 hooks with a timeout of 1-3600 seconds each, up to 16 arguments and 16 environment entries. Arguments are passed as written. Environment values are filled in like script environment variables when the agent claims the backup; after saving, the dashboard shows only their names with "(value kept)".

Saving a hook pins the SHA-256 of the script's shell and code. When either changes later, the hook is suspended and does not run until a user with the hook rights confirms the new version; a deleted script can only be removed. A later save of the policy or of the device settings keeps the pin of a script they already hold, so only **Confirm** approves a changed script. The agent compares the script with its pin once more before it runs it. A suspended hook raises a notification.

**Abort on failure** before the backup or before the snapshot stops the run with "Hook <name> failed in <phase>."; after the snapshot, the remaining hooks of that phase still run before the run fails. **Warn on failure** adds a warning. A failure is a non-zero exit code, a timeout or a suspended hook. After-the-snapshot hooks always run once the before-the-snapshot phase has started; after-the-backup hooks always run and only warn. On a cancel, hooks that have not started yet in the before phases do not start and are reported as skipped; the after phases still run. A service stop ends the run as interrupted ("The agent service stopped."): the agent waits 6 seconds for the after hooks and the final report, then reports the run itself within 3 more seconds; a hook still running then is not waited for and is reported as failed with "The agent service stopped while this hook ran; the script was left running."; the agent does not stop that script, and hooks that have not started by then are reported as skipped. The last 4,096 bytes of standard output and standard error of each hook are kept on the run.

An older agent cannot run hooks: a device whose settings hold hooks makes no backup until its agent is updated ("Update the agent: this backup runs hooks, which older agents cannot run.").

### Readiness checks

The agent sends its readiness checks with each poll and computes them again after a start, after new settings, on **Check now**, when the server wakes it, before each run, on every poll while it is not ready, and otherwise every 6 hours. The server adds its own: `agent.config` (older agents), `agent.sealing`, `agent.platform`, `target.scope` (the target covers the device) and `target.reachable`. A check is Passed, Fixed, Missing, Failed or Manual step; a blocking check that is not passed or fixed makes backups wait with its detail, and losing readiness raises an alert. **Automatic setup** decides what the agent may change by itself: **Apply safe fixes** (`safe`, default) and **Apply all fixes** (`all`) currently apply the same fixes; **Only report what is missing** (`off`) applies none. Every applied fix is audited with its command. Each platform guide lists its checks.

### Backup runs

Each claimed point has a run. **Waiting** means the point is not claimed yet and the reason is shown: the window, AC power, the catch-up delay, a quota, the run limit, readiness, an older agent with hooks, a missing sealed channel or unavailable storage. **Running** shows the step (Snapshot, Scan, Transfer, Verify, Cleanup), bytes read and sent, the rate over 30 seconds, new and reused blocks, deduplication and compression; the agent reports every 5 seconds. **Paused** means the network or AC power is gone. A run ends **Succeeded** after the server verified the point, **Failed** with the reason, **Cancelled**, or **Interrupted**. An interrupted run sends its point back to waiting; the next claim continues and reuses the blocks already stored. A server finds a run interrupted when an agent `1.24.11.2026` or later reports nothing for the pause limit plus 15 minutes ("The agent stopped reporting progress."), and when a point is claimed again after its agent went quiet.

**On battery**: **Wait for AC power** (default) keeps a new run waiting while the device runs on battery. With **Pause on battery** a running backup pauses on battery and continues on AC. A network loss pauses the upload, which is retried every 30 seconds. **Pause limit** (0-240 minutes, default 30) ends a longer pause as interrupted ("Paused longer than <n> minutes." or "On battery longer than <n> minutes."); with 0 there is no pause and the run ends at the first loss. **Bandwidth limits** cap the upload in kbps (1 kbps = 1,000 bit/s), by weekly rules in the device's clock; the first matching rule wins. **Keep awake** holds the device awake during a run. The **SMART check** before each backup warns and goes on, aborts the backup, or is off; a warning raises an alert.

**Cancel run** works until the point is sealed for verification. A connected agent `1.24.11.2026` or later stops at once, runs its after hooks and the point fails with "Backup cancelled by <user>."; for an older or offline agent the server discards the point at once. The log keeps 2,000 lines per run and is cleared 30 days after the run ended; each point keeps its last 20 ended runs. Hook output is shown only to users with Run Script on the device.

### Alerts

Backup alerts have the type Backup and the notification source **Backups**. A device has at most one open alert per kind: a failed run, failures in a row (**Failures before an alert**, default 3), three interruptions in a row, no recent verified backup, a failed verification, refused settings, readiness lost, a used-up quota, a quota over 90 %, and a SMART warning. A succeeded run clears the failure, interruption, verification and staleness alerts. A device is stale when its last verified point is older than the **Recovery point objective**, or by default twice the interval, 48 hours for a daily schedule, or twice the gap between the next two calendar or cron runs; a manual-only device is checked only with a recovery point objective. Notifications without a device cover a target over 90 % or full, a target unreachable for 6 hours and a suspended hook.

### Upgrading from earlier versions

The migration turns every backup folder name into a global backup target; `images` becomes the default target. Existing backup policies become assigned policies with the same settings, and their daily time becomes a daily schedule. A device without a policy keeps all its current values as device settings, so later changes of the Global default do not move it. A policy assigned to such a device later does not replace these values either, because a value set on the device wins: the policy dialog names them for each device, and **Reset to inherited** in the device tab hands a value back to the policy. A device with a policy keeps as device settings only the values that differ from the policy. Devices without settings get a profile without a schedule. Retention tiers start at 0, so migrated devices keep the points that **Keep last** kept before, and the next scheduled run stays as it was. The server resolves 500 devices per minute after the upgrade.

Changes from the earlier device policy dialog: devices that are not ready are no longer dropped from a policy silently, the review list shows them and the user removes them; a policy is deleted in the policy list of the Backups page, not in the device dialog; a policy started from a device takes the device's own settings, not its whole configuration; assigning a policy no longer replaces the values set on the device. A device leaves an assigned policy only when it is removed from the policy's device list, and saving an assigned policy without devices takes every device off it.

Agents before `1.24.11.2026` keep working: the server applies schedules, catch-up, windows, quotas, the run limit, retention, alerts and runs to them, and their scheduled points need no operator. They do not acknowledge settings, report readiness checks or progress, run hooks, wait for AC power, pause or throttle, report agent start and AC power events or end a run at a window end; **Check now** asks to update the agent, and **Cancel run** discards the point on the server.

After a rollback of the server to a version before `1.24.11.2026`, updated agents refuse its backup grants until 24 hours have passed since the last answer of the newer server or until their service restarts. Restart the agent services to resume backups at once.

## Existing Linux offline capture and rescue pairing

1. Prepare a trusted Linux live environment with Python 3.11 or later, util-linux, e2fsprogs, udev and iproute2. Install the recovery tool from this server revision. Boot it in the source system's firmware mode with the kernel argument `ulrmm.recovery=1`. Leave the system partitions unmounted and any swap on them inactive. [Recovery tool](../riddix/scripts/ulrmm_image_recovery.py)
2. At the rescue console run the following preflight as root. It reads the local disk and returns the UUID, disk ID, capacity, sector size and firmware mode on success. Compare these with the intended device before issuing access.

```sh
python3 ulrmm_image_recovery.py --identify capture --disk-id "$source_disk_id"
```

3. In the device's **Backups** tab, choose the backup target, transfer network and compression and save. For a manual backup, select **Request backup**, then **Capture access** for the waiting image and enter the preflight identifiers.
4. Run the following command in recovery and enter the displayed token at the prompt. For an internet-enabled profile, use `--network-mode internet` and omit the interface. For a private CA, add `--ca-file /path/to/ca.pem`.

```sh
python3 ulrmm_image_recovery.py --url "$transfer_url" --disk-id "$source_disk_id" \
  --network-mode internal --interface wg0
```

5. Refresh the device tab. **Verified** records a successful server-side verification of the stored and uncompressed lengths and SHA-256 hashes. Bootability is established by restoring to a test disk and booting it. While waiting, uploading or verifying, the image cannot receive restore access. On interruption, rerun capture for the same offline disk. It regenerates the deterministic stream up to the last committed offset and resumes. If the source changed, discard the incomplete capture and start again. Free space and resume after a storage-full response. Interrupted uploads expire after 24 hours of inactivity.

### Unattended offline capture

Give the device a schedule in its Backups tab or a policy, see [Schedules](#schedules). ULRMM keeps one outstanding request per device while it is off or awaiting offline recovery. The schedule requires a boot window for the rescue environment. Power management and the choice of PXE or physical media belong to the deployment.

For unattended capture, pair the offline device once in the dashboard using its preflight identifiers. Install the pairing secret as a root-readable file on the rescue medium. Run the following command on rescue boot and periodically while the rescue environment is running, for example from a systemd timer. One invocation processes one due request and exits. During a network outage the next invocation can resume. Renew pairing before the displayed expiry or after a change of network mode. A capture grant derived from the pairing stays valid until the pairing expires, so a resumed capture can regenerate a long stream before its first request. Revoking the pairing invalidates its derived grants.

```sh
python3 ulrmm_image_recovery.py --poll-url "$pairing_url" --disk-id "$source_disk_id" \
  --network-mode internal --interface wg0 < /run/credentials/ulrmm-image/token
```

## Linux whole-disk restore

This section covers the offline disk image. A live Linux backup is restored with the same command; the [Linux guide](CLIENT_IMAGING_LINUX.md#restore-a-live-backup) lists its additional steps and requirements.

1. Select the verified image on its source device. Boot the intended target into a trusted Linux recovery environment, preserving the firmware mode. Use `--identify restore --disk-id "$target_disk_id"` to inspect the target. Compare the exact size and sector size with the source. Provision a private staging filesystem on separate recovery storage. Gzip restore needs room for the stored file plus the full raw disk. An uncompressed image needs room for the full raw disk.
2. In **Restore**, select the target device, enter its DMI UUID and stable disk ID, confirm image and target, and complete the two-factor prompt. Use the resulting transfer URL and token on the target.
3. Run the command below as root. The tool downloads and verifies the entire image before requesting the final local confirmation. Check the displayed device, disk and image, then type the displayed phrase. It obtains a fresh authorization and exclusive device handle, writes the disk, flushes it, checks the readback hash and reports completion.

```sh
python3 ulrmm_image_recovery.py --url "$transfer_url" --disk-id "$target_disk_id" \
  --network-mode internal --interface wg0 --staging-dir /mnt/recovery-work
```

4. After successful readback, remove the recovery media and boot the restored disk. If a write is interrupted, keep the disk offline and restart the whole restore from the verified image. ULRMM's deployment ISO builder produces installation media with unattended install steps. Use a dedicated live recovery environment for this procedure.

## Repeat the acceptance test

Use disposable VMs and fresh virtual disks for every writing test. Run the API regression tests with `pytest -q imaging` from `api/ulrmm` in the repository's Django test environment. Run the recovery tool tests with `python3 -m unittest -v test_ulrmm_image_recovery` from `riddix/scripts`.

1. Install or prepare an x86-64 Linux VM with a DMI UUID, a disk serial, and a GPT disk containing an ESP and ext4 root. Reference the local partitions by UUID in fstab. Create a marker file, record `sha256sum` of that file outside the VM, and shut it down cleanly.
2. Follow the capture steps. During upload interrupt the recovery command after the first chunk. Check the committed byte count and absence of Restore, then rerun the command. Verify the image reaches **Verified**.
3. Attach a blank virtual disk of identical capacity and sector size in place of the source. Follow the restore steps using its own serial. Boot from this disk alone and compare the marker checksum. Repeat preflight with a smaller spare disk and check that it receives zero writes.
4. In a separate test store, flip a byte in a stored copy. Restore must stop before opening the disk for writing. Exhaust a disposable storage volume during upload, verify the committed offset, free space and retry. Switch the WireGuard route during transfer with an internet fallback available. Verify the public listener receives zero subsequent internal-mode payloads. Then test a separate internet-enabled job.
5. For Windows, use the Windows guide with a disposable GPT/UEFI guest, healthy VSS writers, all required volumes and WinRE. The provider rejects a BitLocker layout outside its advertised support. For macOS, follow the Intel or Apple Silicon procedure on an authorized spare Mac and validate the migrated account, permissions, applications and agent enrollment.

To repeat the network switch against a TLS receiver on Linux, install WireGuard tools, iproute2, util-linux, OpenSSL and Python, then run `sudo riddix/scripts/test_imaging_network.sh` from a checkout. The test creates two isolated network namespaces. The receiver must see one payload from the tunnel and one from the explicitly permitted direct connection. A third payload attempted by an internal-mode job after tunnel loss must never arrive.

The Linux acceptance VM used a 256 MiB GPT disk with an EFI partition and ext4 root. Capture resumed at byte 4194304 after a forced interruption. After a restore to a fresh disk, the disk SHA-256 was `8d20987edbd47458763444ccc66f19b93a51d71d5035771659f96eed51b93408`. The VM then booted through UEFI and read the original marker with SHA-256 `6e3d2a7e1e2fb1eb7b3f72bcb4b592a514925662a9cd24da28051486f6d8278e`. Each new fixture will have its own hashes.
