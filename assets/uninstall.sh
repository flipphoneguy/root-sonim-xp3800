#!/system/bin/sh

/sbin/su -c "rm /sbin/su; rm /sbin/nsenter; umount /sbin"

exit 0
