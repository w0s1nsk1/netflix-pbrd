#!/bin/sh
set -eu

format=${1:?format: deb, apk, or ipk}
version=${2:?version}
binary=${3:?binary path}
arch=${4:?package architecture}
output=${5:?output directory}

case "$format" in
deb|apk)
	case "$version" in
	[0-9]*) :;;
	*) version="0.0.0~git.$version";;
	esac
	;;
esac

# Alpine versions use the underscore convention for local snapshots.
if [ "$format" = apk ]; then
	version=$(printf '%s' "$version" | sed 's/~/_/g')
fi

mkdir -p "$output"
output=$(cd "$output" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

case "$format" in
deb)
	root="$tmp/root"
	mkdir -p "$root/DEBIAN" "$root/usr/bin" "$root/lib/systemd/system"
	cp "$binary" "$root/usr/bin/netflix-pbrd"
	cp packaging/debian/netflix-pbrd.service "$root/lib/systemd/system/netflix-pbrd.service"
	cat >"$root/DEBIAN/control" <<EOF
Package: netflix-pbrd
Version: $version
Section: net
Priority: optional
Architecture: $arch
Maintainer: netflix-pbrd contributors
Description: DNS-learned Netflix policy-based routing daemon
 Learns trusted Netflix IPv4 destinations and keeps routing/firewall policy synchronized.
EOF
	dpkg-deb --build --root-owner-group "$root" "$output/netflix-pbrd_${version}_${arch}.deb" >/dev/null
	;;
apk)
	command -v abuild-tar >/dev/null 2>&1 || { echo "apk packaging requires abuild-tar" >&2; exit 1; }
	control="$tmp/control"
	data="$tmp/data"
	mkdir -p "$control" "$data/usr/bin" "$data/etc/init.d"
	cp "$binary" "$data/usr/bin/netflix-pbrd"
	cp packaging/openrc/netflix-pbrd "$data/etc/init.d/netflix-pbrd"
	(
		cd "$data"
		find * -print0 | LC_ALL=C sort -z | tar --xattrs \
			--xattrs-exclude=security.selinux --format=posix \
			--pax-option=exthdr.name=%d/PaxHeaders/%f,atime:=0,ctime:=0 \
			--mtime="@0" --no-recursion --null -T - -cf -
	) | abuild-tar --hash | gzip -n -9 >"$tmp/data.tar.gz"
	cat >"$control/.PKGINFO" <<EOF
pkgname = netflix-pbrd
pkgver = $version
arch = $arch
size = $(wc -c <"$binary")
origin = netflix-pbrd
maintainer = netflix-pbrd contributors
license = MIT
description = DNS-learned Netflix policy-based routing daemon
datahash = $(sha256sum "$tmp/data.tar.gz" | awk '{print $1}')
EOF
	tar -C "$control" --format=posix --pax-option=exthdr.name=%d/PaxHeaders/%f,atime:=0,ctime:=0 --mtime="@0" -cf - .PKGINFO | abuild-tar --cut | gzip -n -9 >"$tmp/control.tar.gz"
	cat "$tmp/control.tar.gz" "$tmp/data.tar.gz" >"$output/netflix-pbrd-${version}-${arch}.apk"
	;;
ipk)
	control="$tmp/control"
	data="$tmp/data"
	mkdir -p "$control" "$data/usr/sbin" "$data/etc/init.d"
	cp "$binary" "$data/usr/sbin/netflix-pbrd"
	cp packaging/openwrt/netflix-pbrd.init "$data/etc/init.d/netflix-pbrd"
	cat >"$control/control" <<EOF
Package: netflix-pbrd
Version: $version
Architecture: $arch
Section: net
Priority: optional
Maintainer: netflix-pbrd contributors
Description: DNS-learned Netflix policy-based routing daemon
EOF
	printf '2.0\n' >"$tmp/debian-binary"
	tar -C "$control" --format=ustar -czf "$tmp/control.tar.gz" control
	tar -C "$data" --format=ustar -czf "$tmp/data.tar.gz" .
	( cd "$tmp" && ar -cr "$output/netflix-pbrd_${version}_${arch}.ipk" debian-binary control.tar.gz data.tar.gz )
	;;
*)
	echo "unknown package format: $format" >&2
	exit 2
	;;
esac
