# Windows system images

Use **More → System images** on the enrolled Windows device. The Windows agent reports its current readiness, selected disk, capture scope and recovery procedure. Start a manual capture or set the daily time and time zone there. Capture uses Microsoft Windows Backup with VSS copy semantics and all boot-critical volumes. The agent requires stable VSS writers before and after the backup, including the System Writer and Registry Writer, and checks for a Windows Backup catalog version before uploading. The server verifies the complete TAR stream. Each point carries its own Windows catalog and can be staged on a new disk on its own. The storage profile controls transfer compression. [Windows VSS writer identities](https://learn.microsoft.com/en-us/windows/win32/vss/in-box-vss-writers)

The initial layout is x64 Windows 11 24H2 or Windows Server 2025 and later builds, UEFI, one GPT boot disk, an EFI system partition and MSR, one NTFS Windows partition with BitLocker fully decrypted, and Windows RE registered on the same disk's recovery partition. Extra partitions on the OS disk, legacy BIOS, encrypted Windows volumes and cross-hardware migration require separate procedures. Application data or operating-system components on other disks are outside this capture scope. The capability is probed on the device. The supported-layout gate checks technical eligibility. See the acceptance status below for evidence on specific versions and hardware. [Microsoft VSS](https://learn.microsoft.com/en-us/windows/win32/vss/the-vss-model) · [Windows Backup capture](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wbadmin-start-backup) · [Windows RE deployment](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/deploy-windows-re)

Microsoft lists the Windows client System Image Backup feature as deprecated. The reference uses the current Windows Server Backup feature on Server 2025. Windows 11 capture depends on the native command and recovery tools continuing to be available on the exact client release. [Windows client feature deprecations](https://learn.microsoft.com/en-us/windows/whats-new/deprecated-features)

## Prepare the capture agent

1. Deploy an imaging-aware ULRMM agent. On Windows Server, install Windows Server Backup from elevated PowerShell. Install the BitLocker feature and restart if the Windows BitLocker WMI provider is absent. ULRMM reads the provider to confirm that the system volume is fully decrypted. The feature itself is independent of volume encryption.

   ```powershell
   Install-WindowsFeature Windows-Server-Backup,BitLocker -IncludeManagementTools
   reagentc /info
   vssadmin list writers
   ```

2. Attach a dedicated, local, fixed NTFS staging disk with one data partition and a drive letter. Size it for one full copy of the protected volumes. The staging target must be a different disk from the Windows system. Configure its root to grant access only to SYSTEM and Administrators. Run the commands as a local administrator and replace `S:` with the dedicated staging volume, after checking the disk and volume in Disk Management.

   ```powershell
   $stagingRoot = 'S:\'
   $stagingId = (mountvol $stagingRoot /L | Where-Object { $_ -match 'Volume\{' }).Trim()
   $acl = [System.Security.AccessControl.DirectorySecurity]::new()
   $acl.SetSecurityDescriptorSddlForm('O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
   Set-Acl -LiteralPath $stagingRoot -AclObject $acl
   New-ItemProperty 'HKLM:\SOFTWARE\UniversalLocalRMM' -Name ImagingStagingVolume `
     -PropertyType String -Value $stagingId -Force
   ```

3. Provision enough local staging and server space for a complete image. After a transfer interruption, the agent reuses the same local Windows Backup set for the same image request. It frees that set once the server accepts the complete stream for verification. If the final response was lost, the agent asks the server about the previous image before it reuses the staging volume. It clears the retained set when that image is verified, failed or discarded. It keeps the set while the image still waits, uploads or verifies, and while the server cannot be reached. The agent marks `.ulrmm-imaging.json` as unfinished before Windows Backup starts and as complete after the VSS and catalog checks. If the agent stops or Windows Backup fails in between, the next capture waits until Windows Backup is idle, clears that unfinished set and runs a new backup. Review Microsoft-Windows-Backup events after a failed run. The agent never removes staging content without a valid ULRMM ownership record. Inspect such content locally.

4. For an internal-only policy, provision the official Windows WireGuard client and set `ULRMM_IMAGING_INTERFACE` in the ULRMM agent service environment to the running tunnel's adapter alias. Restart the agent service after setting it. The Windows agent binds outbound transfer sockets to the corresponding active WireGuardNT adapter. The server must also validate ingress on its dedicated VPN listener and write to the approved storage. Use the internal topology described in the main runbook. Transfer authentication uses the enrolled agent. Windows Backup stages on local NTFS before ULRMM sends any backup bytes. Local staging and server copies contain sensitive data and need their own protection independently of source-volume encryption. [Client imaging infrastructure](CLIENT_IMAGING.md) · [WireGuard for Windows tunnel service](https://git.zx2c4.com/wireguard-windows/tree/tunnel/service.go)

## Restore a selected Windows image

Use separate Windows recovery media matching the OS generation and x64/UEFI configuration. Keep the source offline and detach its disk throughout recovery. Use a replacement system disk and a separate dedicated NTFS staging disk. Use a trusted recovery or staging workstation to run the bundle download using the restore grant. The original agent is unnecessary for retrieval.

1. Before authorizing the restore, boot the target into a trusted UEFI Linux rescue environment with the kernel parameter `ulrmm.recovery=1` and the replacement drive attached. Read the actual machine DMI UUID, stable whole-disk ID, exact capacity and logical sector size. Match the approved target, source disk geometry and UEFI mode. Use `lsblk` and `wipefs --no-act` to verify the replacement has no partitions or existing signatures. Record the serial and controller position. Keep this attachment unchanged up to the Windows recovery confirmation.

   ```sh
   sudo python3 ulrmm_image_recovery.py --identify restore --disk-id "$blank_disk_id"
   lsblk -b -o NAME,SIZE,LOG-SEC,MODEL,SERIAL,TYPE
   sudo wipefs --no-act "/dev/disk/by-id/$blank_disk_id"
   ```

2. Select the verified image, target device and approved disk in ULRMM and use the separate restore authorization. Enter the disk size and sector size from the preflight; ULRMM refuses a disk smaller than the source disk or one with another sector size. Supply the scoped token on standard input. Download to a new file on a sufficiently large, private staging workstation. For internal-only transfers supply `--network-mode internal --interface` and the provisioned WireGuard interface. For a grant that explicitly allows internet access, use `--network-mode internet`. For a private TLS CA use `--ca`.

   ```sh
   ulrmm-agent imaging-fetch --url "$grant_url" --image "$image_id" \
     --target "$target_agent_id" --disk "$blank_disk_id" --output windows-system.tar
   ```

   If the download stops, run the same command again. It continues from `windows-system.tar.<first 16 hex digits of the SHA-256>.partial` next to the output. Write the output to a folder that only the operator can write to. On Linux and macOS the tool refuses a partial file that belongs to another user or that others can write; on Windows it does not check the owner or permissions of that file.

3. Stage the verified uncompressed TAR to the root of the dedicated NTFS volume. Obtain the uncompressed SHA-256 from the verified transfer or its manifest. The extractor verifies that digest before creating any files. On Windows, use the NTFS volume's root without quoting a trailing backslash in CMD, for example `--staging-root S:\`. On Linux use an `ntfs3` mount for the dedicated volume.

   ```sh
   python3 ulrmm_windows_image_stage.py --archive windows-system.tar \
     --sha256 "$verified_uncompressed_sha256" --staging-root /mnt/windows-stage
   ```

4. Safely dismount the NTFS volume and preserve it as the verified catalog base. In the QEMU reference, create an empty writable overlay backed by that base and attach the overlay as the separate catalog disk. For a physical lab, use a dedicated writable copy of the verified catalog. Boot Windows RE from external optical recovery media in UEFI mode with only the approved blank target and the catalog disk attached. Use `diskpart` commands `list disk`, `select disk <n>`, `detail disk` and `list volume` to cross-check both disks against the prior physical preflight. Identify the NTFS volume containing `WindowsImageBackup` by reading the directory in WinRE. The drive letter may differ from the staging workstation. Use `wbadmin get disks` to identify the catalog disk for exclusion. Stop before confirming any target write if WinRE reports RAW, the catalog cannot be read, or either disk cannot be positively identified.

   ```sh
   qemu-img create -f qcow2 -F raw -b /absolute/path/verified-ntfs-catalog.raw winre-catalog-view.qcow2
   ```

5. Query the native catalog for the staged computer and confirm the selected version. The computer name is the machine directory directly under `WindowsImageBackup`. Review the backup's recovery capabilities and abort if Windows does not report bare-metal recovery. Exclude the catalog disk from partition recreation. Replace `R:`, the example version, machine name and the excluded disk ID with the values observed locally. Keep the interactive confirmation. [Windows Backup version inventory](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wbadmin-get-versions) · [Windows bare-metal restore](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wbadmin-start-sysrecovery)

   ```cmd
   wbadmin get versions -backupTarget:R: -machine:CAPTURED-COMPUTER
   wbadmin get disks
   wbadmin start sysrecovery -version:11/22/2026-10:00 -backupTarget:R: -machine:CAPTURED-COMPUTER -recreateDisks -excludeDisks:{STAGING-DISK-ID}
   ```

6. Detach both the staging disk and recovery media and boot from the restored disk with networking disabled. Verify login, Windows RE using `reagentc /info`, the data and access rules. From ULRMM's **Agent certificate…** dialog, quarantine the old identity to revoke the restored copy's token and certificates. Keep the old device record while its imaging points are needed. Use the authorized local uninstall on the restored target if the old agent is present. Enroll with a fresh site installer over the trusted recovery network and verify the new online identity before normal network access.

## Disposable VM acceptance

The accepted reference is Microsoft Windows Server 2025 Datacenter Evaluation x64, en-US, build 26100.1742, on QEMU q35 with OVMF and software CPU emulation. The disposable copy of Microsoft's published VHDX had a 68,719,476,736-byte GPT SATA disk with 512-byte logical sectors, a 200 MiB ESP, a 128 MiB MSR, a 67,268,130,304-byte NTFS Windows partition and a 1 GiB NTFS recovery partition. BitLocker was off. Capture used a dedicated 96 GiB NTFS SATA staging disk. The external recovery environment came from the Windows Server 2025 evaluation ISO 26100.32230 and reported WinRE build 26100.1. Both fresh 64 GiB restore targets had distinct SATA serials. [Microsoft evaluation media](https://www.microsoft.com/en-us/evalcenter/download-windows-server-2025)

On a disposable factory VHDX copy, shrink NTFS and create a dedicated 1 GiB NTFS recovery partition. Set its final Windows recovery GPT type and attributes before assigning a temporary drive letter and registering `Winre.wim` with `reagentc /setreimage` and `reagentc /enable`. Remove the temporary letter and confirm that `reagentc /info` reports Windows RE enabled on partition 4. Attach the separate NTFS staging volume. [Windows RE deployment](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/deploy-windows-re)

1. Enroll the source. Create three pieces of fixture state under `C:\ULRMM-Acceptance`: an unchanged reference, a file to change and a file to remove. Set a test ACL for a local user and record independent SHA-256 values with `Get-FileHash`, the user SID and object ACLs with `Get-Acl`.
2. Start the first backup from **System images**. Check for a verified record. Change the second file, remove the third and add a new file. Run the next backup through the normal schedule or the same manual path. Record the exact original and changed checksums externally.
3. Switch off and remove the source disk. Restore the latest point using the steps above. Boot with that disk alone and test Windows login, checksums, removal, new file, permissions and WinRE. Reenroll and confirm a secure online check-in. Restore the first point separately and repeat the comparison against the earlier fixture.
4. Test a smaller blank disk, a corrupted bundle, a full destination and an unauthorized restore. Confirm that none reaches the WinRE write step. Interrupt upload after at least one committed chunk and restore connectivity. For internal-only transport, switch the route away from WireGuard and confirm the public listener sees no further upload bytes. Repeat with an internet-enabled configuration.
5. Record the installed build, VM disk IDs, firmware and sector sizes, BitLocker state, writer and catalog results, the two restore job outcomes and secure check-ins. Keep the capture, catalog verification, restore and boot results separate.

The Windows provider and tests cross-compile for x64. Its parser, archive and staging ownership tests passed under Wine 10.0. The agent running as SYSTEM on the 26100.1742 VM passed the native system disk, WinRE, BitLocker, staging volume and VSS writer checks. Windows Backup saved the EFI system partition, the Windows partition and the recovery volume. The catalog version `11/22/2026-13:15` reported Bare Metal Recovery and System State. ULRMM verified the first requested capture of 12,447,010,304 raw bytes after receiving 6,656,904,515 new stored bytes at gzip level 1. The complete raw SHA-256 was `371d894b9866e23e285e32f88c865287d718f3806a35114641a92d21f140fc21`.

The follow-up job confirmed verification of the first point with the server before clearing its retained native staging set. Windows Backup reported Bare Metal Recovery and System State for catalog version `11/22/2026-14:16`. The test stopped the SYSTEM uploader after the server committed 1,573 blocks covering 3,298,820,096 raw bytes. The same job retained its native catalog and reused the previously stored blocks. A subsequent write to an intentionally full isolated test filesystem returned HTTP 507 and the agent surfaced the storage error. After the original storage became available, ULRMM verified the resumed point of 12,478,474,240 raw bytes. It referenced 6,647,139,128 stored bytes at gzip level 1, including 460,806,791 new bytes. The complete raw SHA-256 was `d8caea93ac5252a84292f2cfcc84bf8bbad6458ae59839c56da7a4ca4e836273`. The first point stayed verified with the same hash.

The Windows transport test used the official Authenticode-signed WireGuard 1.1.1 client and a native WireGuardNT adapter. The imaging transport sent a synthetic HTTPS payload from the tunnel address with its configured private CA. After the tunnel stopped, an independent direct connection reached the same HTTPS address and port from the Ethernet adapter. The existing internal transport refused to reconnect.

After the original VM shut down, a dashboard role without restore authorization received HTTP 403 and obtained no grant. A corrupted block on an isolated copy of the real Windows manifest caused the recovery CLI to abort with HTTP 409 and leave no TAR. A complete recheck of the original point preserved its verified state.

The staging extractor read back a synthetic catalog on a freshly formatted 128 MiB NTFS volume. Its automated tests exercise digest verification, refusal to overwrite and rejection of unsafe Windows archive names and links. On the actual WinRE target, a hardware-read-only catalog disk appeared as RAW and returned a write-protection error. The first NTFS boot sector had zero partition-start and legacy geometry values. WinRE still reported RAW with those values populated. It read the protected catalog base successfully after attaching its writable QCOW2 overlay.

The Linux recovery preflight detected both blank virtual targets through their distinct SATA serials, each with 68,719,476,736 bytes, 512-byte logical sectors and the expected UEFI target UUID. WinRE storage discovery set each disk's four-byte MBR identifier without creating partitions. Perform the Linux identity and capacity checks before booting into WinRE. With the source shut down and detached, operators obtained each restore grant through a fresh TOTP step-up. The independent recovery CLI downloaded both TARs and verified the complete hashes above. External WinRE recreated each approved target separately and restored its EFI, Windows and recovery volumes from the selected native catalog.

Each point booted directly from its own restored disk through Windows Boot Manager with the network link disabled. The original local administrator logged in on each. On the follow-up, the changed and added files had the expected SHA-256 values and the deleted file was absent. On the initial point, the earlier file version and the subsequently deleted file matched their original hashes, and the later addition was absent. The unchanged reference file matched both its digest and its access rule for the enabled local account SID. Both boots used the EFI BCD path and reported WinRE enabled on partition 4.

The old Windows identity was quarantined through a separate TOTP step-up and its previous API access changed from HTTP 200 to 403. Each restored guest then joined the recovery site with its own signed one-time deployment. Both registered a new active Sec2 token family and authenticated to the NATS broker with their new NKeys over TLS. The server issued and verified a sealed RPC ping with a genuine `pong` from each restored Windows agent.
