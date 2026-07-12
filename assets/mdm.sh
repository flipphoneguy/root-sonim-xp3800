#!/system/bin/sh
set -e
trap 'mount -o ro,remount /system 2>/dev/null' EXIT

PACKAGE="com.verizon.mdm.basicphone"
DEVICE_OWNER_SYSTEM="/system/etc/device_owner_2.xml"
DEVICE_OWNER_DATA="/data/system/device_owner_2.xml"
DEVICE_POLICIES="/data/system/device_policies.xml"
RC1="/system/etc/VZW_XP3800.rc"
RC2="/system/etc/init/VZW_XP3800.rc"

remove() {
    mount -o rw,remount /system

    if [ -f "$DEVICE_OWNER_SYSTEM" ] && [ ! -f "$DEVICE_OWNER_SYSTEM.bak" ]; then
        mv "$DEVICE_OWNER_SYSTEM" "$DEVICE_OWNER_SYSTEM.bak"
    fi

    for rc in "$RC1" "$RC2"; do
        if [ -f "$rc" ] && [ ! -f "$rc.bak" ]; then mv "$rc" "$rc.bak"; fi
    done

    printf '<?xml version='\''1.0'\'' encoding='\''utf-8'\'' standalone='\''yes'\'' ?>\n<root>\n</root>\n' > "$DEVICE_OWNER_DATA"

    if [ -f "$DEVICE_POLICIES" ] && [ ! -f "$DEVICE_POLICIES.bak" ]; then
        mv "$DEVICE_POLICIES" "$DEVICE_POLICIES.bak"
    fi

    pm disable "$PACKAGE" 2>/dev/null || true

    mount -o ro,remount /system
    sync
}

restore() {
    if [ ! -f "$DEVICE_OWNER_SYSTEM.bak" ]; then
        echo "No backup found — removal was never performed on this device."
        exit 1
    fi

    mount -o rw,remount /system

    mv "$DEVICE_OWNER_SYSTEM.bak" "$DEVICE_OWNER_SYSTEM"
    cp "$DEVICE_OWNER_SYSTEM" "$DEVICE_OWNER_DATA"

    for rc in "$RC1" "$RC2"; do
        if [ -f "$rc.bak" ]; then mv "$rc.bak" "$rc"; fi
    done

    if [ -f "$DEVICE_POLICIES.bak" ]; then
        mv "$DEVICE_POLICIES.bak" "$DEVICE_POLICIES"
    fi

    pm enable "$PACKAGE" 2>/dev/null || true

    mount -o ro,remount /system
    sync
}

case "$1" in
    remove)  remove ;;
    restore) restore ;;
    *)       echo "Usage: mdm.sh remove|restore"; exit 1 ;;
esac
