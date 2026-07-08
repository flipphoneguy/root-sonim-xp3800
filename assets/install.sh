#!/system/bin/sh

export TMPDIR="/data/data/com.flipphoneguy.root.xp3/cache"
cd "/data/data/com.flipphoneguy.root.xp3/files" || exit 1
LOG="install.log"
DIR=$(pwd)

VERBOSE=""
[ "$1" = "-v" ] && VERBOSE="-v"

echo "Starting install..." > "$LOG"

{
    echo "--- ENVIRONMENT ---"
    id
    ls -l "$DIR"

    echo "--- PERMISSIONS ---"
    /system/bin/chmod 755 su

    echo "--- EXPLOIT START ---"
    ./su $VERBOSE -c "
        echo 'Exploit triggered shell!'
        /system/bin/mount -o remount,rw /system
        /system/bin/cp '$DIR/su' /system/bin/su
        /system/bin/chown 0:0 /system/bin/su
        /system/bin/chmod 0755 /system/bin/su
        /system/bin/mount -o remount,ro /system
        ls -l /system/bin/su
        echo 'SUCCESS'
    "

} >> "$LOG" 2>&1

if [ -f "/system/bin/su" ]; then
    exit 0
else
    echo "FAILED: /system/bin/su not found after run" >> "$LOG"
    exit 1
fi
