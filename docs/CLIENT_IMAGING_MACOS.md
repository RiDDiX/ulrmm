# macOS system recovery from ULRMM

ULRMM uses Time Machine to capture apps, accounts, settings and user data, subject to Time Machine exclusions. The agent then archives the dedicated external APFS Time Machine disk as `macos-timemachine-disk-v1`. The archive retains Time Machine's dated backups and APFS metadata. Recovery installs macOS on the target first and imports the selected history with Setup Assistant or Migration Assistant. [Apple Time Machine restore](https://support.apple.com/en-sg/102551) · [Apple signed system volume](https://support.apple.com/guide/security/signed-system-volume-security-secd698747c9/web)

| Architecture | Reference test configuration | Recovery after loss of startup storage |
| --- | --- | --- |
| Intel | An Intel Mac running macOS 13 Ventura or later with a normal APFS System/Data volume group | Start with Command–R. If local Recovery is gone, use Option–Command–R for Internet Recovery. Install macOS, then migrate from the reconstructed Time Machine disk. A T2 Mac may also require Apple's firmware procedure if Recovery cannot start. |
| Apple silicon | An Apple silicon Mac running macOS 13 Ventura or later with a normal APFS System/Data volume group | Hold the power button to enter startup options and choose Options. Install macOS, then migrate from the reconstructed Time Machine disk. If firmware or recoveryOS cannot start, follow Apple's revive or restore procedure with a second Mac. For failed soldered storage, use a repaired Mac or a replacement Mac. |

The archive is migration media. Its APFS snapshots contain recoverable data and application state within Time Machine's scope. The Apple installer creates the signed System volume, boot components and recovery environment on the destination. With FileVault enabled the running source Mac must already be unlocked. Inspect the source FileVault state and Time Machine disk encryption separately in the device's capability. Escrow the Time Machine disk password separately from the source Mac and confirm storage encryption on the ULRMM server. Even an APFS encrypted backup disk can expose partition metadata in its raw archive. [Intel Recovery](https://support.apple.com/guide/mac-help/use-macos-recovery-on-an-intel-based-mac-mchl338cf9a8/mac) · [Apple silicon Recovery](https://support.apple.com/guide/mac-help/macos-recovery-a-mac-apple-silicon-mchl82829c17/mac) · [DFU firmware recovery](https://support.apple.com/en-us/108900) · [FileVault](https://support.apple.com/guide/security/volume-encryption-with-filevault-sec4c6dc1b6e/web)

## Prepare the source Mac

1. Connect a dedicated external physical GPT disk with one EFI partition and one APFS container. Give it one Time Machine Backup volume. In **System Settings → General → Time Machine**, select it as a local destination and choose **Manually** under **Options → Backup Frequency**. Let ULRMM schedule subsequent runs. Use an empty dedicated test disk when setting up acceptance. The archive includes all sectors of that disk, including unallocated and deleted data. Apple recommends APFS or APFS Encrypted for directly attached Time Machine media. [Apple supported destinations](https://support.apple.com/en-gb/guide/mac-help/mh15139/mac) · [Time Machine settings](https://support.apple.com/en-euro/guide/mac-help/mh14037/27/mac/27)
2. In **System Settings → Privacy & Security → Full Disk Access**, grant access to the installed signed ULRMM service executable. Restart the agent to apply the change. Grant access to the executable identity used by the system service. A grant for the operator's Terminal covers commands run from that Terminal. Review the application's backup consistency procedures and confirm that essential paths pass `tmutil isexcluded <path>`. The agent uses `tmutil listbackups` to check access from the service context. [Apple access to files](https://support.apple.com/guide/security/controlling-app-access-to-files-in-macos-secddd1d86a6/web)
3. Run `tmutil destinationinfo` and record the **ID** and **Mount Point** for the local destination. Use `diskutil info "<mount point>"` to record the APFS **Volume UUID** and its **APFS Physical Store** disk identifier. Run `diskutil info <physical store>` and record its **Disk / Partition UUID**. Create `/etc/ulrmm-imaging.json` as a regular file owned by root with mode `0600`. Use each identifier from the corresponding command.

   ```json
   {
     "destination_id": "00000000-0000-0000-0000-000000000001",
     "volume_uuid": "00000000-0000-0000-0000-000000000002",
     "partition_uuid": "00000000-0000-0000-0000-000000000003"
   }
   ```

4. Keep the dedicated disk connected and unlocked. In the device's **System images** view, inspect the agent's scope, encryption state and readiness. Configure the backup profile and request a run. The agent starts a blocking Time Machine capture addressed to the pinned destination, requires a newly completed backup and unmounts the disk while reading its sectors. It attempts to remount the volume afterward. If the agent stops before that, the next readiness check mounts the attached volume again. If APFS relocks it, unlock it before the next capture. Leave the destination idle while ULRMM reads it. The agent compares the APFS container transaction ID before and after the read and fails the capture if the disk was written. The agent records the Time Machine date per active backup job. After an interrupted transfer it reuses that date while it is still the latest on the disk. If a newer Time Machine backup appeared, the agent starts a new backup for the same job.

The native capture uses Apple's built-in `tmutil`, `diskutil`, `fdesetup` and `ioreg`. The documented CLI contracts are available on the Mac under `man tmutil`, `man diskutil` and `man ioreg`. The agent uses its existing `howett.net/plist` v1.0.0 dependency for Apple's property lists. It is BSD-3-Clause and follows the normal ULRMM agent dependency and update process. [Agent third-party notices](../ulrmm-agent/THIRD_PARTY_NOTICES.md)

Each completed server archive contains the entire local Time Machine disk as of that run. Time Machine saves only changes to the local history after the initial capture. The shared ULRMM storage and compression determine any savings when exporting that history to the server. Raw encrypted sectors and free space can be expensive to export. The server verifies stored bytes. The macOS migration test separately verifies that the archive can be consumed by Apple's assistant. Internet-enabled transfers use the shared HTTPS path. Internal-only transfers require the verified WireGuard setup below.

### Internal-only transfer

Use a root-operated `wireguard-go` tunnel with one approved peer and a fixed `utunN` interface. Assign the tunnel IP to that interface and direct the internal imaging HTTPS listener through it. Set up the server-side VPN ingress and private storage checks from the [main runbook](CLIENT_IMAGING.md#internal-ingress). macOS tunnels without a protected WireGuard userspace API socket leave internal transfers waiting.

Install the upstream-supported `wg` binary as root at a regular file path with root-owned, non-group/world-writable directories. WireGuard's documented upstream releases include `wireguard-go` 0.0.20250522 and `wireguard-tools` 1.0.20260223. The deployment operator maintains these optional tools (WireGuard Go is MIT-licensed and WireGuard Tools is GPLv2). ULRMM uses the installed binary for the public-peer check. [WireGuard releases](https://git.zx2c4.com/wireguard-go/refs/tags) · [WireGuard tools releases](https://git.zx2c4.com/wireguard-tools/refs/tags) · [macOS tunnel support](https://git.zx2c4.com/wireguard-go/tree/README.md)

Create the regular root-owned `/etc/ulrmm-imaging-wireguard.json` file with mode `0600`. Replace the interface, address, public key and executable path with locally approved values.

```json
{
  "interface": "utun12",
  "source_ip": "10.77.0.12",
  "peer_public_key": "APPROVED_PUBLIC_PEER_KEY",
  "wg_path": "/usr/local/libexec/ulrmm/wg"
}
```

For each HTTPS connection, the client verifies that the interface is up, owns the configured IP and has a root-only `/var/run/wireguard/<interface>.sock`. It runs `wg show <interface> peers` and requires the single approved public key. It binds the TCP socket to the verified interface index and source IP, then checks the interface and UAPI socket again before returning the connection to the HTTPS client. The server independently verifies the peer on the dedicated VPN listener. [WireGuard UAPI socket](https://git.zx2c4.com/wireguard-go/tree/ipc/uapi_unix.go) · [Apple IPv4 socket option](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet/in.h) · [Apple IPv6 socket option](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet6/in6.h)


## Restore to a fresh system

1. From a separate authorized administrator session, select the verified macOS point and obtain an image-scoped restore grant. On a working Mac with the current agent binary available, run the command below and enter the grant token at the prompt. The tool writes the output at a new path and verifies its complete contents. An interrupted download stays next to the output as `<output>.<first 16 hex digits of the SHA-256>.partial`, and running the same command again continues from it. Write the output to a folder that only you can write to; the tool refuses a partial file that belongs to another user or that others can write. The tool removes a download that fails verification. Record its raw size and SHA-256 before touching recovery media. Keep the source Mac and original Time Machine disk disconnected. For an internal-only grant, run the download with the verified tunnel setup as root and use `--network-mode internal --interface utun12`, substituting the configured interface.

   ```sh
   ulrmm-agent imaging-fetch --url "$grant_url" --image "$image_id" \
     --target "$approved_target_agent_id" --disk "$approved_disk_id" \
     --network-mode internet --output /path/to/verified-time-machine.raw
   ```
2. On a working Mac, connect one explicitly disposable external physical disk with the same byte capacity and logical sector size shown on the point. Confirm its identity against `diskutil list external physical` and `diskutil info /dev/diskN`. Use the verified raw archive as input and the identified disposable **whole external disk** as output. The following writes to that disk. Recheck its identifier immediately before the write. The `if` argument is the archive file and `of` is the confirmed external device.

   ```sh
   diskutil unmountDisk /dev/diskN &&
     sudo dd if="/path/to/verified-time-machine.raw" of=/dev/rdiskN bs=1m &&
     sync &&
     sudo zsh -o pipefail -c 'dd if=/dev/rdiskN bs=1m | shasum -a 256'
   diskutil eject /dev/diskN
   ```

   Compare the readback digest with the expected raw SHA-256 before using the disk. Stop if the disk size or digest differs. Keep the media attached only to the recovery target when using Migration Assistant, since it has the same partition and volume UUIDs as the original.
3. Start the target through the native Apple Recovery path in the table and install the same or a later compatible macOS release onto the startup disk. Connect the reconstructed Time Machine disk. On first setup, choose **From a Mac, Time Machine backup or startup disk**. If setup is complete, open Migration Assistant in **Applications → Utilities**. Unlock the archive when prompted. Choose the newest Time Machine date in the disk reconstructed from the selected ULRMM point, then choose the agreed accounts, applications, settings and data. Once macOS installation has finished, isolate the recovery target from the ULRMM server before migration. [Recover all files from a Time Machine backup](https://support.apple.com/en-au/guide/mac-help/mh15638/mac)
4. Sign in to the restored account. Verify account and shared folder permissions and open the designated applications. Check FileVault and the recovery key on the restored startup volume. If Migration Assistant brought over the prior agent, use its local `-m uninstall` mode on the isolated recovery target, with the site's authorized uninstall code when required. Revoke the old credentials with the source device record retained for its recovery points. Provision the freshly signed agent from a site installer and verify its new identity in ULRMM before returning the recovered Mac to the normal network.

## Acceptance on disposable hardware

The macOS provider reads native command output with the existing agent dependency `howett.net/plist` v1.0.0 (BSD-3-Clause). Its license is included in the agent's third-party notices. Updates follow the agent's normal pinned Go dependency and signing process. Apple supplies and updates Time Machine, Recovery and Migration Assistant with macOS.

| Test | Intel | Apple silicon |
| --- | --- | --- |
| Native agent build and test compilation | Go 1.27.3 Darwin amd64 passed | Go 1.27.3 Darwin arm64 passed |
| Time Machine first and subsequent backup | Pending Mac | Pending Mac |
| Actual archive verification | Pending Mac | Pending Mac |
| Disk reconstruction and Migration Assistant | Pending Mac | Pending Mac |
| First boot, login, application data and permissions | Pending Mac | Pending Mac |
| Agent re-enrollment | Pending Mac | Pending Mac |

Run the following on an authorized spare Intel Mac and Apple silicon Mac. A VM on Apple hardware can validate a specific guest/macOS configuration using Apple's Virtualization framework. Physical startup security, T2, firmware recovery and physical storage replacement require hardware tests. [Apple Virtualization framework](https://developer.apple.com/documentation/virtualization/installing-macos-on-a-virtual-machine?changes=la_5&language=objc)

1. Record Mac model, Intel/T2 or Apple silicon, `sw_vers`, APFS System/Data and backup layout with `diskutil apfs list`, source FileVault with `fdesetup status` and backup medium encryption. Start with no backup history on the dedicated disk. Create a test user, three app data markers covering file content, extended attributes and ACLs, and an app-specific data fixture. Record hashes and `ls -le@` output outside the source system.
2. Assign the policy and run the first point from the device view. Confirm the native Time Machine date with `sudo tmutil listbackups -d "<mount point>" -t` and record the archived size/hash. Change a file, remove a second and create a third, then take a scheduled point. Record the next native date and repeat the metadata check.
3. Take the source Mac and original backup disk offline. Restore each point on separate fresh startup installations using its own reconstructed Time Machine archive. Compare hashes for both dates and check that the removed file is absent and the added file is present only for the later point. Sign in with the expected users and check UID, functional application data, xattrs, ACLs, FileVault unlock and re-enrollment.
4. Interrupt an upload and test a full disposable server store. Confirm previous verified points stay available and an incomplete point stays ineligible for recovery. Corrupt a copy of the stored archive, then confirm server verification or download validation rejects it before the disk write. Attempt restore with an account lacking restore permission. With the internal-only policy, first verify that captures wait when the UAPI socket or approved peer is unavailable. Test a successful routed transfer with the dedicated WireGuard setup. During the next upload, take down the tunnel while the public route stays available and verify the public receiver receives zero subsequent imaging bytes.
5. Record both point IDs, native Time Machine dates, raw SHA-256 readbacks, first boot and login, application checks and re-enrolled agent identity. Record which tests used a VM and which used physical hardware.

No authorized macOS test system was available in the Linux development environment. Native Time Machine execution, readback, Apple Recovery, Migration Assistant and agent re-enrollment all remain pending for both architectures.
