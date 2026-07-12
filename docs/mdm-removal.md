# Removing Verizon MDM

Verizon ships the XP3800 with `com.verizon.mdm.basicphone` as Android **Device Owner** — the highest privilege level an app can hold short of the OS itself. As device owner it can silently install/remove apps, block settings, and manage the phone like an enterprise MDM.

The app provides a toggle in the About screen to remove or restore device-owner status. The card only appears on Verizon devices (detected via `PackageManager`).

---

## Device-Owner Persistence

Android tracks device-owner state in two files:

| File | Purpose |
|---|---|
| `/system/etc/device_owner_2.xml` | Firmware copy, re-synced to `/data/system/` on every boot by init scripts. |
| `/data/system/device_owner_2.xml` | Runtime copy read by `DevicePolicyManagerService` at boot. |

Editing only the runtime copy doesn't stick — two init scripts (`/system/etc/VZW_XP3800.rc` and `/system/etc/init/VZW_XP3800.rc`) contain a `post-fs-data` action that copies the firmware version back over it on every boot:

```
on post-fs-data
    copy /system/etc/device_owner_2.xml /data/system/device_owner_2.xml
    chown system system /data/system/device_owner_2.xml
    chmod 0771 /data/system/device_owner_2.xml
```

Both `.rc` files are identical — duplicated across Android's two init-script search paths.

---

## Removal

`assets/mdm.sh remove` (run via `su -c`):

1. Remounts `/system` read-write.
2. Renames `/system/etc/device_owner_2.xml` to `.bak`.
3. Renames both `.rc` files to `.bak`, disabling the boot-time re-sync.
4. Overwrites `/data/system/device_owner_2.xml` with an empty `<root/>` document — `DevicePolicyManagerService` reads this at boot and sees no device owner.
5. Renames `/data/system/device_policies.xml` to `.bak` (orphaned policy state).
6. Runs `pm disable` on the MDM package.
7. Remounts `/system` read-only, syncs.

Every rename is guarded with `[ -f X ] && [ ! -f X.bak ]` so re-running is a no-op. The script runs with `set -e` and a trap that remounts `/system` read-only on any exit, so a partial failure doesn't leave `/system` writable.

`pm disable` takes effect immediately — the app stops and can't launch. The device-owner flag is cached in memory by `DevicePolicyManagerService` until the next reboot, but with the app disabled it has no practical effect.

## Restore

`assets/mdm.sh restore`:

1. Checks for `device_owner_2.xml.bak` — exits with an error if removal was never performed.
2. Remounts `/system` read-write.
3. Renames all `.bak` files back to their original names.
4. Copies the restored `/system/etc/device_owner_2.xml` to `/data/system/device_owner_2.xml`.
5. Runs `pm enable` on the MDM package.
6. Remounts read-only, syncs.

After restore and reboot, the device is identical to one that was never modified.
