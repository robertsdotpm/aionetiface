# Setting up WinPcap on Windows XP (one-time, manual)

The userspace pcap workaround for the XP `tcpip.sys` simul-open RST
(see `/home/x/projects/warpgate/CLAUDE.md` "Windows XP cross-NAT
tcp_punch is not fixable from user-space") needs WinPcap 4.1.3
installed on every XP node that wants to act as a TCP-punch listener.

WinPcap 4.1.3 is the LAST version that supports Windows XP. Npcap
dropped XP support after release 0.07; do not attempt to install
Npcap on XP -- the NDIS 5 callouts it expects are not present.

> Why this is a manual step: WinPcap's NSIS installer launches a
> custom plugin (`WinPcapInstall.dll`) for the "Auto-start NPF"
> wizard page that does NOT honour `/S` silent mode on Windows XP
> SP3. The installer hangs at that page waiting for input even when
> driver-signing is set to Ignore and the rest of the install is
> non-interactive. Extracting the bundled files with 7-Zip and
> registering the NPF kernel service by hand fails with SCM event
> 7000 (`The system cannot open the file`) on the shipped npf.sys
> binary, likely because the installer's `WinPcapInstall.dll` plugin
> performs additional driver-signing / Catalog steps that we are
> not replicating. After about 90 minutes of trying the automation
> paths we punted to "run the installer once by hand", which is what
> the rest of this doc covers.

## Verify SHA-256 first

Download from <https://www.winpcap.org/install/default.htm> and check:

```
fc4623b113a1f603c0d9ad5f83130bd6de1c62b973be9892305132389c8588de  WinPcap_4_1_3.exe
```

The same hash is published widely (security vendor mirrors, archive.org)
so the integrity check is meaningful.

## One-time install on the XP VM

1. RDP / console into the XP machine as a user in `Administrators`.
2. Run `WinPcap_4_1_3.exe` from Explorer.
3. Click through the dialogs:
   - Welcome -> Next
   - License -> I Agree
   - Installation options -> leave "Automatically start the WinPcap
     driver at boot time" CHECKED. We need it pre-loaded so the
     SCM `start npf` from our test harness succeeds without admin.
   - Install -> Finish.
4. From an admin `cmd.exe` verify:

```cmd
sc query npf
```

Expected output includes `STATE : 4 RUNNING`. If it says STOPPED:

```cmd
sc start npf
```

5. Confirm the user-space libraries are reachable:

```cmd
dir C:\Windows\System32\wpcap.dll
dir C:\Windows\System32\Packet.dll
```

Both should exist and be dated 2013.

## Verifying from Python

From the matthew user shell (no admin needed once NPF is running):

```cmd
C:\py3\python.exe -c "from aionetiface.net.pcap import get_backend; b = get_backend(); print(b.library_version()); print(b.list_interfaces())"
```

Expected: a version string starting with `WinPcap version 4.1.3` and
a list with at least one entry whose `name` looks like
`\Device\NPF_{guid}`.

## Driver signing note (XP SP3)

If you want to disable the Windows-Logo-not-passed prompt during the
GUI install, set the driver-signing policy to Ignore before running
the installer:

```cmd
reg add "HKLM\Software\Microsoft\Driver Signing" /v Policy /t REG_BINARY /d 00 /f
```

`00 = Ignore`, `01 = Warn (default)`, `02 = Block`. Restore to `01`
after install if you care about the prompt for other drivers.

## VMs in our test matrix

XP test VM lives at `matthew@10.0.1.132`, password is set per
`reference_windows_machines.md` in the user's memory. The installer
EXE has been pre-staged at:

```
C:\Documents and Settings\matthew\winpcap_install.exe
```

So the manual install is just: RDP in, double-click that file,
click through. ~30 seconds.

If the VM is reset or rebuilt, re-stage from a fresh download (URL
+ SHA-256 above).

## Modern Windows (Vista+, Windows 7, 8, 10, 11)

Use Npcap from <https://npcap.com/#download>. Install with the
"WinPcap-compatible mode" checkbox CHECKED -- that is what makes
`wpcap.dll` discoverable at `C:\Windows\System32\Npcap\wpcap.dll`
and what our `WindowsFactory` shim searches for. On Windows 7+ the
silent install does work: `npcap-1.79.exe /S /winpcap_mode=yes`
(adjust version). Modern Windows hosts in the sweep matrix can be
automated through the orchestrator scripts in
`/home/x/projects/warpgate_test_run/` once we wire that up.
