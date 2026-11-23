# Linux system images

The Linux agent detects the system disk and reports the source disk identifier, firmware mode, sector size, capacity, and recovery requirements to ULRMM. On the reference layout it requests an offline maintenance window. Start the same ULRMM agent binary from trusted recovery media after the installed OS has shut down. It takes an exclusive read-only handle to the authorized disk and runs the offline filesystem and boot-layout checks before it streams any image bytes.

## Reference configuration

| Component | Linux offline capture |
| --- | --- |
| System | x86-64 Linux, UEFI, GPT, one directly partitioned ext4 root. |
| Boot | FAT EFI System Partition with the bootloader, plus any same-disk ext4 `/boot`. The whole-disk image preserves the bootloader files, initramfs, partition UUIDs, filesystem UUIDs and persistent mount references. |
| Disk identity | Valid DMI product UUID and a stable whole-disk `/dev/disk/by-id` identifier. |
| Filesystem and application consistency | Shut down the installed OS and applications cleanly. Leave the source partitions unmounted and swap inactive in the recovery environment. Linux rejects an ext4 partition that needs journal recovery. |
| Restore | Use a fresh disk with equal byte capacity and logical sector size. Boot in the original UEFI mode. If the firmware lost its boot entry, use the restored EFI loader through firmware setup. The QEMU fixture uses the standard `EFI/BOOT/BOOTX64.EFI` path and disposable OVMF variables. |

| Layout | Support |
| --- | --- |
| ext4 | Offline with the above layout. Same-disk ext4 data partitions are included. |
| FAT EFI partition | Included with the offline disk. |
| LVM and LUKS | No supported capture. |
| XFS and Btrfs | No supported capture. |
| RAID and multiple disks | RAID across disks has no supported coordinated capture. Only the system disk is imaged: mounts on other local disks, network shares and swap on other disks are left out and listed as "Not included" in the device's backup scope. `/`, a separate `/boot` and the EFI partition must be on the system disk. The check resolves `UUID=`, `PARTUUID=`, `LABEL=` and `PARTLABEL=` sources and their `/dev/disk/by-*` links, accepts swap files, skips bind mounts and `noauto` entries without `x-systemd.automount`, such as the installer's optical drive. A label that several partitions share is refused. Data on the left-out disks needs its own backup. On other hardware, attach those disks or mark their fstab entries `nofail` from the recovery media before the first boot; without `nofail` the system stops in emergency mode, and `x-systemd.device-timeout=10s` shortens the 90-second wait for each missing disk. |
| BIOS, Secure Boot and physical hardware | The native reference path is UEFI. Secure Boot and physical hardware need acceptance on the actual configuration. |

A disk image includes unallocated blocks and may expose remnants of deleted data. Network transport uses HTTPS. Verify the encryption configuration at the backup destination before enabling the policy. A clean offline reboot gives a filesystem-consistent disk, with application consistency depending on each application's shutdown behavior.

## Prepare the recovery media

Use a trusted x86-64 Linux rescue image with Python 3.11 or later, util-linux, e2fsprogs and udev. For an internal-network-only policy, provide iproute2, the WireGuard kernel driver and the required VPN configuration. The normal agent build publishes `ulrmm-agent-v<version>-linux-recovery-amd64.tar.gz` with the Linux agent and [ULRMM recovery helper](../riddix/scripts/ulrmm_image_recovery.py) together. Obtain the bundle from your ULRMM server's build output. Unpack it into a temporary directory, run `sha256sum -c SHA256SUMS` there and install the two verified files as root-owned regular files under `usr/bin` and `usr/lib/ulrmm` in the media's root. Replace both files when rebuilding the media for an update. Obtain supporting packages and security updates from the rescue distribution. The installer ISO performs unattended installation. A recovery image requires a separate live boot with no automatic source mounting or swap activation. Rebuild the recovery media from the bundle of each new agent version; an older helper may refuse a system that the current agent accepts.

For the source and target, boot rescue mode with the kernel argument `ulrmm.recovery=1`. At the rescue console, confirm the selected disk.

```sh
python3 /usr/lib/ulrmm/ulrmm_image_recovery.py --identify capture --disk-id "$disk_id"
```

## Capture and restore

1. Open **System images** on the device. Review the capability report, choose compression and network access, and request an image or configure a schedule. A scheduled run waits for the chosen recovery window.
2. After a clean shutdown, boot the recovery media and verify the disk identity displayed by preflight. Request **Capture access** for the waiting image. Use the direction-specific URL and token displayed there.
3. Run the following on the recovery system. Provide the token on standard input through a file owned and readable only by root. For internal-only transfers change to `--network-mode internal --interface wg0`. For a private CA add `--ca /path/to/ca.pem`.

```sh
ulrmm-agent imaging-capture --url "$transfer_url" --image "$image_id" \
  --target "$agent_id" --disk "$disk_id" --network-mode internet < "$token_file"
```

4. Check **Verified** on the selected image. If a transfer fails, keep the source disk unchanged and offline before retrying an interrupted transfer.
5. Follow the [restore access, staging and readback procedure](CLIENT_IMAGING.md#linux-whole-disk-restore). Restore runs from trusted recovery media even when the old agent and disk are unavailable. Keep the original machine disconnected when restoring its identity. After boot, verify the user login, file data and ownership, and the existing agent's secure check-in. If the server no longer accepts the saved credentials, use the normal ULRMM agent enrollment procedure.

For unattended recovery-window capture, the [paired offline poll command](CLIENT_IMAGING.md#daily-backups) passes native jobs and their scoped credentials to `/usr/bin/ulrmm-agent`. Native restore needs a separate staging filesystem with free space for one complete raw disk. The recovery helper validates all retrieved blocks and the assembled raw image, rechecks the live grant and disk, then compares the disk readback hash before reporting completion. It retries each request up to five times after a network error or an HTTP 502, 503 or 504 reply.

## Reference acceptance

The disposable QEMU 10.0.13 x86-64 fixture used OVMF, a Debian 13 kernel (`6.12.117+deb13-amd64`) and a minimal userspace. It had one unencrypted 256 MiB virtio disk with 512-byte logical sectors, GPT, a FAT ESP with the fallback loader and an ext4 root. The installed agent reported its layout over authenticated HTTPS. The capture ran the Linux agent from recovery and used gzip and the native block formats. Both raw image SHA-256 digests matched their respective source disks.

| Check | First point | Follow-up point |
| --- | --- | --- |
| New compressed bytes stored | 182,006,332 | 4,205,626 |
| Raw SHA-256 | `b55a5670a734f692ada5e9b8d1e12288b76a7f1df1fa5b47beba110a46a8bc42` | `6bfe1d6c5fc7d850dda11a6b324cfa1142375f7c1980fbfdbfc7650320d306ce` |
| Restore and boot | Whole-disk readback matched and UEFI boot succeeded from a blank replacement disk | Whole-disk readback matched and UEFI boot succeeded from another blank replacement disk |
| File states | Original content verified, old file present, new file absent | Changed content and new file verified, old file absent |
| User and modes | Account session ran as UID/GID 1000 and read the file at mode 0640 | Account session ran as UID/GID 1000, changed file at mode 0640 and new file at mode 0600 |
| TTY login | Wrong password rejected, temporary test password accepted | Wrong password rejected, temporary test password accepted |
| Agent reattachment | ULRMM accepted the HTTPS agent inventory from the replacement disk | ULRMM accepted the HTTPS agent inventory from the replacement disk |
| Fresh secure enrollment | Existing-record HTTPS verification | Signed deployment enrolled a new device, TLS NATS accepted its NKey, and sealed RPC returned `pong` |

The original fixture had a locked password field. In the supplementary password test, the restored root filesystems were booted with a separate QA initramfs and a QEMU snapshot. A salted temporary password hash was bind-mounted over `/etc/shadow` from tmpfs. BusyBox `getty` and `login` authenticated the restored account on the serial TTY, where both file checks passed again. Both raw disk hashes stayed unchanged. The test covered the restored user account and shell access with a QA password. The fixture does not use PAM or store a usable password hash in either backup.

The server rejected the restored agent token with HTTP 401 after revocation, then accepted the replacement disk's inventory after a fresh ULRMM REST credential was issued. This exercised the TLS agent inventory endpoint on the existing device record.

The separate secure enrollment test started the actual Linux agent on a QEMU snapshot of the follow-up disk. The lab signed an expiring one-use deployment and used the normal `-m install -enroll` and `-m svc` entry points. ULRMM registered an active Sec2 identity, issued a token family and rendered the broker configuration with the new NKey. The isolated broker authenticated that NKey over TLS 1.3. A real Sec2 request from the server received the agent's sealed `pong` response. The minimal fixture launched the service entry point directly and used a new device record. Distribution-specific systemd supervision and mTLS client certificates require separate acceptance.

To repeat the test, use a disposable UEFI VM with the reference layout and make two files readable by a dedicated test user. Record the user ID, group ID, modes and SHA-256 checksums. Capture the first point. Boot the test VM, modify one file, delete the other and create a new file. Record the new values, shut down cleanly and capture the follow-up point. Keep the original VM offline during restore. For each point, restore to a separate blank disk with fresh OVMF variables, boot that disk alone, log in as the test user, and compare `id`, `stat`, `sha256sum` and the expected deletion state with the external record. Verify that the server registers a fresh agent inventory from the replacement disk.

To exercise failure paths, interrupt an upload after the server records an offset and retry the point with the source unchanged. Use a disposable backup store to test full storage and damage a required block before restoring. The recovery helper must stop before it opens the target disk for writing when a block is missing or corrupt. Try restore access from a user without the Restore permission and confirm that no grant is issued. On the internal-only path, remove the WireGuard peer while a direct route exists and confirm the receiver observes no internal-only payload on that route.

In the reference lab the native upload recovered from an interruption at 2,097,152 bytes and both older points remained verified. The native collector refused the source while its root partition was mounted and matched the whole-disk hash after unmounting it. The TLS receiver in the WireGuard test received the initial tunnel payload and the explicitly internet-enabled retry. It received zero internal-mode payloads after the direct route became the fallback.

A separate QA point with a damaged required block failed during staging, and the blank target's SHA-256 remained unchanged. The Linux API returned HTTP 507 for a full, isolated 1 MiB filesystem, retained the previous verified point, and verified the retried point after space was freed. An authenticated dashboard user without Restore permission received HTTP 403 when requesting a restore grant.

## Technical references

- UrBackup Linux client 2.5.31 offers kernel/device-mapper snapshot workflows, and its server supports incremental image chains. The Linux installer detects LVM and Btrfs and offers the applicable snapshot methods. A volume snapshot leaves GPT, the ESP and boot-critical partitions outside that volume to a separate capture mechanism. [UrBackup Linux 2.5.31 release](https://github.com/uroni/urbackup_backend/releases/tag/2.5.31client) · [Installer snapshot selection](https://github.com/uroni/urbackup_backend/blob/9e6b1c3e4baa4dca05262a1c0940ccd9a36a41dd/install_client_linux.sh#L499-L575) · [Server administration manual](https://www.urbackup.org/administration_manual.html)
- Clonezilla Live 3.3.3-37 uses Partclone 0.3.50 and saves used filesystem blocks while the source is unmounted. ULRMM uses that offline consistency model and preserves the whole disk for the supported layout. The larger read is traded for preserving on-disk boot layout and allowing byte-for-byte readback. ULRMM does not distribute Clonezilla or Partclone. [Clonezilla release notes](https://clonezilla.org/downloads/stable/release-notes.php) · [Clonezilla limitations](https://clonezilla.org/)
