#!/system/bin/sh

/system/bin/su -c "
    fuser -k /data/local/tmp/.su.sock 2>/dev/null
    rm -f /data/local/tmp/.su.sock /data/local/tmp/.su.lock
    mount -o remount,rw /system
    rm -f /system/bin/su
    mount -o remount,ro /system
"

exit 0
