# Removing Verizon MDM

This document explains what the "Remove Verizon MDM" / "Restore Verizon MDM" feature does, why it works the way it does, and a native-library bug found and fixed while testing the restore path.

---

## Table of Contents

- [What It Does](#what-it-does)
- [Why Editing the Runtime Files Alone Doesn't Work](#why-editing-the-runtime-files-alone-doesnt-work)
- [Removal](#removal)
- [Restore](#restore)
- [The Forced Reboot](#the-forced-reboot)
- [Failure Handling](#failure-handling)
- [The Native Library Bug](#the-native-library-bug)
- [Where It Lives](#where-it-lives)

---

## What It Does

Verizon ships the XP3800 with `com.verizon.mdm.basicphone` installed as **Android Device Owner** — the highest privilege level an app can hold short of being part of the OS itself. As device owner it can silently install/remove apps, block settings, and generally manage the phone the way an enterprise MDM manages a work phone.

The "Remove Verizon MDM" button on the main screen strips this app of device-owner status and disables it, leaving the phone with **no device owner at all**. "Restore Verizon MDM" reverses it — re-enables the app and puts it back as device owner, undoing a previous removal.

Both actions force an **immediate hard reboot** to apply the change (see [The Forced Reboot](#the-forced-reboot)), so both are gated behind a confirmation dialog first.

---

## Why Editing the Runtime Files Alone Doesn't Work

Android tracks device-owner state in three places:

| File | Role |
|---|---|
| `/system/etc/device_owner_2.xml` | Firmware-baked copy. Read-only under normal operation, but re-copied to `/data/system/` on every boot. |
| `/data/system/device_owner_2.xml` | The runtime copy `DevicePolicyManagerService` actually reads. |
| `/data/system/device_policies.xml` | Per-admin policy state (restrictions, active-admin flags, etc.) tied to the device owner. |

Editing only the `/data/system` runtime copy looks like it works — until the next reboot, when Android copies the firmware-baked `/system/etc/device_owner_2.xml` back over it and Verizon MDM's device-owner status silently returns. The fix has to touch **both** copies, or it doesn't stick.

---

## Removal

`MdmRemover.remove()` builds a small root shell script and runs it via `su -c`:

1. `mount -o rw,remount /system` — the XP3800 has no dm-verity, so `/system` is freely remountable (see the main [README](../README.md#modifying-system)).
2. Look up the installed path of `com.verizon.mdm.basicphone` via `pm path` and rename the APK to `<path>.bak`. This is naturally idempotent — if it's already been removed, `pm path` returns nothing and this step is skipped.
3. Back up the current `device_owner_2.xml` and `device_policies.xml` (first run only — an existing backup is never overwritten, so repeated removals don't clobber the real original).
4. Overwrite `device_owner_2.xml` in **both** `/system/etc/` and `/data/system/` with an empty `<root></root>` document — this is the actual fix for the persistence problem above.
5. Delete `/data/system/device_policies.xml` (orphaned once there's no device owner).
6. Remount `/system` read-only, `sync`, and force a reboot.

## Restore

`MdmRemover.restore()` undoes exactly the above, using the backups written during removal:

1. Refuses to run if no backup exists (i.e., removal was never performed on this device).
2. Remounts `/system` read-write.
3. Moves the `.bak` APK back to its original name.
4. Re-extracts the app's native library (see [below](#the-native-library-bug) — this step doesn't exist in the original design and was added after the bug surfaced).
5. Copies the backed-up `device_owner_2.xml` back to both locations, and `device_policies.xml` back to `/data/system/` if it was backed up.
6. Remounts read-only, `sync`, and forces a reboot.

---

## The Forced Reboot

Both operations end with:

```sh
sync
echo b > /proc/sysrq-trigger
```

This is an immediate, unclean kernel-level reboot — not `reboot` or Android's normal shutdown sequence. It's deliberate: a graceful shutdown gives `DevicePolicyManagerService` a chance to run its own persistence logic and write Verizon's device-owner state back out before the device actually restarts, undoing the change we just made. The hard reboot skips that entirely. `sync` immediately beforehand flushes pending writes so the abrupt restart doesn't corrupt the filesystem.

---

## Failure Handling

Both shell scripts run with `set -e`, so any failed step (a failed remount, a failed `cp`) aborts the script **before** it reaches the reboot line. Without this, a partial failure would still hard-reboot the device and report success to the app, because the script's last command (the `echo` to `sysrq-trigger`) always succeeds regardless of what happened earlier.

---

## The Native Library Bug

The first real test of `restore()` crashed Verizon MDM on boot with:

```
java.lang.UnsatisfiedLinkError: ...couldn't find "libsqlcipher.so"
```

The cause: Android doesn't load a priv-app's native libraries straight out of its APK zip at runtime. `PackageManagerService` extracts them once, at package-scan time, into a separate directory next to the APK — `<apkDir>/lib/<instruction-set>/` (e.g. `/system/priv-app/VerizonMDM/lib/arm/`), where the instruction-set name (`arm`) differs from the ABI folder name inside the APK zip (`armeabi-v7a`).

Renaming the APK away and back makes `PackageManagerService` treat the app as uninstalled and then reinstalled. On the reinstall scan it tries to redo that native-library extraction — but by the time the post-reboot boot scan runs, `/system` is already back to read-only (our script already remounted it ro before rebooting), so the extraction silently fails. The app comes back as device owner with its APK intact, but `lib/arm/libsqlcipher.so` never got recreated, and `dumpsys package` shows `primaryCpuAbi=null` as the tell.

The fix: `restore()` now extracts `lib/armeabi-v7a/libsqlcipher.so` directly out of the (still `.bak`-named) APK's own zip in Java — priv-app APKs are world-readable, so this needs no root — and copies it into `<apkDir>/lib/arm/` itself, in the same root shell script, before `/system` goes back to read-only. This makes the fix self-contained rather than relying on Android to redo work it can no longer do at that point in the boot sequence.

---

## Where It Lives

- `src/com/flipphoneguy/root/xp3/MdmRemover.java` — `remove()` / `restore()` and the native-lib extraction helper.
- `src/com/flipphoneguy/root/xp3/MainActivity.java` — confirmation dialogs, background threading, and the button/status wiring on the main screen (`btn_remove_mdm`, `btn_restore_mdm`, `mdm_status`).
- `res/layout/activity_main.xml`, `res/values/strings.xml` — the UI card and its copy.
