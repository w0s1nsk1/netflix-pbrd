#!/system/bin/bash

/system/bin/wg-quick up wg0 >> /opt/wireguard_log.txt

PATH=/opt/bin:/opt/sbin:/system/bin:/system/xbin:$PATH
ps | grep '[c]rond' >/dev/null 2>&1 || /opt/sbin/crond

(
  attempt=0
  while [ "$attempt" -lt 60 ]; do
    if ip link show wg0 >/dev/null 2>&1 && iptables -t nat -S PRE_REDIRECT >/dev/null 2>&1; then
      break
    fi
    attempt=$((attempt + 1))
    sleep 5
  done
  /opt/sbin/netflix-pbr-watchdog
) >> /opt/netflix-pbr-boot.log 2>&1 &
