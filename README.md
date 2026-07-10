# Root Sonim XP3800

Root access for the Sonim XP3800. Two methods are available — choose whichever fits your situation.

## Root Manager App

The Root Manager app exploits CVE-2019-2215 (a binder use-after-free kernel vulnerability) to gain root directly on the device. No computer, no bootloader unlock, no flashing required. The exploit binary is a ground-up ARM32 port targeting the XP3800's 3.18.71 kernel — every kernel structure offset was derived from reverse engineering the device's kernel binary.

Install the APK via ADB (the XP3800 blocks APK installation from the device itself), tap Install, and root is permanently written to `/system/bin/su`. Root persists across reboots with no boot service or background process — the binary is just there, like any other system command.

```sh
adb install RootManager.apk
```

### How it works

The first time `su` is invoked after a boot, it runs the kernel exploit (~1.2 seconds) and spawns a persistent root daemon. Every subsequent `su` call connects to the daemon instantly (~0.13 seconds) — no exploit, no kernel manipulation. The daemon enters PID 1's mount namespace via `setns()`, so commands have full filesystem access including `/system`.

The exploit is serialized with `flock()` to prevent concurrent runs (which would panic the kernel) and retries up to 3 times on failure.

### Features

- **Persistent root** — `su` is installed to `/system/bin` permanently. No tmpfs, no boot receiver, survives reboots and factory resets.
- **Writable /system** — The XP3800 has no dm-verity. `/system` is plain ext4, freely remountable read-write. Changes persist across reboots.
- **Root app installer** — Install APKs and split APKs (XAPK) using root, since the XP3800 blocks app installation without ADB. Also registers as a handler for APK files from file managers.
- **Remove Verizon MDM** — Strip Verizon's `com.verizon.mdm.basicphone` of device-owner status and disable it (or restore it). See [Removing Verizon MDM](docs/mdm-removal.md).
- **Daemon architecture** — Exploit runs once per boot, daemon handles all subsequent requests. The daemon is protected from Android's low-memory killer (`oom_score_adj = -1000`). See [The Daemon](docs/daemon.md).
- **Denylist** — Block specific apps from using `su`. Filter by User/System/All, search by name or package.
- **Install diagnostics** — View install logs and re-run the exploit with verbose logging from the About screen.
- **Self-update** — Checks GitHub Releases for newer versions and installs via root.
- **D-pad friendly** — Full keyboard/d-pad navigation with visible focus states.

### Usage

| Command | Description |
| :--- | :--- |
| `su` | Interactive root shell (preserves caller's environment) |
| `su -c 'cmd'` | Run a command as root (uses system shell and PATH) |
| `su cmd` | Same as `-c` |
| `su -p -c 'cmd'` | Run a command preserving the caller's full environment |
| `su --preserve-environment -c 'cmd'` | Same as `-p` |
| `su -s bash -c 'cmd'` | Specify shell |
| `su --daemon` | Start the root daemon manually (requires root) |
| `su --mount-master` | Accepted for compatibility (no-op — daemon already has full mount namespace) |
| `su -v` | Verbose exploit output |

### Access control

The `su` binary has a built-in denylist. By default, any app can use `su` unless it's in the denylist. Manage the denylist from the app's main screen — check the box next to any app to block it.

Termux and ADB shell (`uid 2000`) are always allowed regardless of the denylist. Wildcard entries like `com.example.*` are supported.

## Magisk Method

The alternative is flashing a patched boot image via Qualcomm's EDL mode and QFIL.

**Important details:**

- Use **Magisk 24.0.0** specifically. Leave all Magisk options at their defaults — don't toggle anything.
- The boot image **must come from your device**. Pull it via EDL/QFIL, or use this app + `dd` once rooted. Do not download boot images from the internet — other variants or firmware versions may not match your device and could fail to boot.
- If Magisk's file picker doesn't work on the XP3800 (it sometimes doesn't), try a different file manager app like FX, or patch the boot image from another phone that has Magisk 24.0.0 installed.

## Modifying /system

The XP3800 has **no dm-verity** — the `/system` partition is a plain ext4 filesystem with no integrity checking. The `androidboot.veritymode=enforcing` flag is set in the kernel cmdline but is a complete no-op: there are no dm-verity device mapper devices, no vbmeta partition, and no hash tree.

```sh
su -c "mount -o remount,rw /system"
# make your changes
su -c "mount -o remount,ro /system"
```

Changes persist across reboots. **Be careful what you delete** — removing the wrong system file can bootloop the device.

## Build

Requires Termux with `aapt2`, `ecj`, `d8`, `apksigner`, `zip`, and `~/.android/{android.jar,framework-res.apk,debug.keystore}`.

```sh
./build.sh
```

Output: `RootManager.apk`

## Technical details

The exploit and its implementation are documented in detail:

- [CVE-2019-2215: The Exploit Explained](docs/CVE-2019-2215.md) — The vulnerability, every background concept, and the full escalation chain from UAF through root
- [The ARM32 Port](docs/arm32-port.md) — What breaks on 32-bit ARM and how it's fixed
- [The Daemon](docs/daemon.md) — How the daemon provides persistent root without re-running the exploit
- [Removing Verizon MDM](docs/mdm-removal.md) — How device-owner removal and restore works

## Disclaimer

This software is provided as-is with no warranty. The author assumes no responsibility for bricked, broken, or otherwise damaged devices. Use at your own risk.

## License

[GPLv3](LICENSE)
