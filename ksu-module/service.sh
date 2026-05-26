#!/system/bin/sh

MODDIR="${0%/*}"
KO="$MODDIR/selinux_seqno_fix.ko"
PARAM="/sys/module/selinux_seqno_fix/parameters/enabled"

if [ -e "$PARAM" ]; then
  echo 1 > "$PARAM" 2>/dev/null
  exit 0
fi

if [ -r "$KO" ]; then
  insmod "$KO" 2>/dev/null
fi
