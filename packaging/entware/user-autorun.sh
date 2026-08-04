#!/system/bin/sh

PATH=/opt/bin:/opt/sbin:/system/bin:/system/xbin:$PATH
CONFIG=${NETFLIX_PBR_RELAY_CONFIG:-/opt/etc/netflix-pbr-relay.conf}

if [ -r "$CONFIG" ]; then
	. "$CONFIG"
	[ -z "$OUTER_WG_QUICK_CONFIG" ] || /system/bin/wg-quick up "$OUTER_WG_QUICK_CONFIG"
fi

ps | grep '[c]rond' >/dev/null 2>&1 || /opt/sbin/crond
/opt/sbin/netflix-pbr-watchdog >> /opt/netflix-pbr-boot.log 2>&1 &
