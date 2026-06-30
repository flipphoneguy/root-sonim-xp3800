#!/system/bin/sh

export TMPDIR="/data/data/com.flipphoneguy.root/cache"
cd "/data/data/com.flipphoneguy.root/files" || exit 1
LOG="install.log"
DIR=$(pwd)

echo "Starting install..." > "$LOG"

# capture everything
{
    echo "--- ENVIRONMENT ---"
    id
    ls -l "$DIR"
    
    echo "--- PERMISSIONS ---"
    /system/bin/chmod 755 su
    /system/bin/chmod 755 nsenter
    
    echo "--- EXPLOIT START ---"
    # Run the exploit
    ./su -s sh << EOF
        echo "Exploit triggered shell!"
        
        # Mount /sbin if needed
        if ! /system/bin/grep -qs "tmpfs /sbin" /proc/mounts; then
             echo "Mounting /sbin..."
             /system/bin/mount -t tmpfs tmpfs /sbin
        fi

        # Copy binaries
        echo "Copying binaries..."
        /system/bin/cp "$DIR/su" /sbin/su
        /system/bin/cp "$DIR/nsenter" /sbin/nsenter

        # Set permissions
        /system/bin/chmod 755 /sbin/su
        /system/bin/chmod 755 /sbin/nsenter
        
        # Verify
        ls -l /sbin/su
        echo "SUCCESS"
        exit
EOF

} >> "$LOG" 2>&1

if [ -f "/sbin/su" ]; then
    exit 0
else
    echo "FAILED: /sbin/su not found after run" >> "$LOG"
    exit 1
fi
