# Root Sonim XP3800

Root access for the Sonim XP3800 (XP3plus). Two paths are available — choose whichever fits your situation.

## Two paths to root

### Option 1: EDL/QFIL (flash a patched boot image)

This is the more traditional method. You extract the stock boot image from your device, patch it with Magisk, and flash it back via Qualcomm's EDL mode and QFIL.

**Important details:**

- Use **Magisk 24.0.0** specifically. Leave all Magisk options at their defaults — don't toggle anything.
- The boot image **must come from your device**. Pull it via EDL/QFIL, or use this app + `dd` once rooted. Do not download boot images from the internet — other variants or firmware versions may not match your device and could fail to boot.
- If Magisk's file picker doesn't work on the XP3800 (it sometimes doesn't), try a different file manager app like FX, or patch the boot image from another phone that has Magisk 24.0.0 installed.

### Option 2: Root Manager app (CVE-2019-2215, no PC needed)

This app exploits a kernel vulnerability to gain root directly on the device — no computer, no bootloader unlock, no flashing. Install the APK, tap to root. This is what the rest of this README covers.

## Root Manager

The Root Manager app bundles a prebuilt exploit binary (`su`) targeting CVE-2019-2215 (Binder use-after-free), tuned for the XP3800's 3.18.71 ARM32 kernel. On install:

1. The exploit gains kernel R/W and escalates to uid 0
2. Mounts a tmpfs at `/sbin` and copies `su` + `nsenter` there
3. `/sbin/su` is now available system-wide for root access

Since `/sbin` lives in RAM (tmpfs), root is lost on reboot. The boot receiver re-runs the exploit automatically on each boot to make it persistent.

### Features

- **Root toggle** — Tap the status card to install or uninstall root
- **Boot persistence** — Automatically re-roots on device boot
- **App blacklist** — Block specific apps from using `su`. Filter by User/System/All, search by name or package.
- **APK/XAPK installer** — Install APKs and split APKs (XAPK) using root. Also registers as a handler for APK files from file managers.
- **Self-update** — Checks GitHub Releases for newer versions and installs via root
- **D-pad friendly** — Full keyboard/d-pad navigation with visible focus states

### Usage

The app installs `su` at `/sbin/su`. Any app or terminal can use it:

| Command | Description |
| :--- | :--- |
| `su` | Root shell |
| `su -c "cmd"` | Run a command as root and exit |
| `su cmd` | Same as above |
| `su -s bash` | Specify shell (default is `$SHELL`) |
| `su -v` | Verbose output |

### Access control

The `su` binary has a built-in whitelist/blacklist system:

- **Blacklist mode** (default): Any app can use `su` unless it's in the blacklist. Manage the blacklist directly from the app's main screen.
- **Whitelist mode**: If a `whitelist.txt` file exists and is non-empty in the app's data directory, only listed apps can use `su`. All others are denied.
- Termux and ADB shell are always allowed regardless of list configuration.

## Build

Requires Termux with `aapt2`, `ecj`, `d8`, `apksigner`, `zip`, and `~/.android/{android.jar,framework-res.apk,debug.keystore}`.

```sh
./build.sh
```

Output: `RootManager.apk`

## Technical details

The exploit and its ARM32 port are documented in detail:

- [CVE-2019-2215: The Exploit Explained](docs/CVE-2019-2215.md) — Full background on the vulnerability and escalation chain
- [The ARM32 Port](docs/arm32-port.md) — What breaks on 32-bit ARM and how it's fixed

## Warning

**Do not use root to modify `/system` or other protected partitions.** Doing so can permanently brick the device. If you don't know what that means, only use root for installing apps. Use at your own risk — the author assumes no responsibility for bricked devices.

## License

[GPLv3](LICENSE)
