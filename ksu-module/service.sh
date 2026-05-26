#!/system/bin/sh

MODDIR="${0%/*}"
KO="$MODDIR/selinux_seqno_fix.ko"
PARAM="/sys/module/selinux_seqno_fix/parameters/enabled"
LOG="$MODDIR/load.log"

log_msg() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') $*" >> "$LOG"
}

log_params() {
  for name in enabled hits fixups no_policyload null_avd last_old_seqno last_live_seqno; do
    path="/sys/module/selinux_seqno_fix/parameters/$name"
    if [ -r "$path" ]; then
      log_msg "$name=$(cat "$path" 2>/dev/null)"
    fi
  done
}

: > "$LOG"
log_msg "kernel=$(uname -r)"

if [ -e "$PARAM" ]; then
  echo 1 > "$PARAM" 2>/dev/null
  log_msg "module already loaded; enabled=1"
  log_params
  exit 0
fi

if [ ! -r "$KO" ]; then
  log_msg "missing ko: $KO"
  exit 1
fi

if insmod "$KO" >> "$LOG" 2>&1; then
  log_msg "insmod ok"
  if [ -e "$PARAM" ]; then
    echo 1 > "$PARAM" 2>/dev/null
    log_msg "enabled=1"
  fi
  log_params
else
  rc=$?
  log_msg "insmod failed rc=$rc"
  dmesg | tail -n 40 >> "$LOG" 2>/dev/null
  exit "$rc"
fi
