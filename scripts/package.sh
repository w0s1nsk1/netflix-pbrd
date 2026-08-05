#!/bin/sh
set -eu

format=${1:?format: deb, apk, or ipk}
version=${2:?version}
binary=${3:?binary path}
arch=${4:?package architecture}
output=${5:?output directory}

case "$format" in
deb)
	case "$version" in
	[0-9]*) :;;
	*) version="0.0.0~git.$version";;
	esac
	;;
apk)
	case "$version" in
	*[._-]*) :;;
	*) version="0.0.0_git~$version";;
	esac
	;;
esac

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
	data="$tmp/data"
	command -v apk >/dev/null 2>&1 || { echo "apk packaging requires apk-tools v3" >&2; exit 1; }
	mkdir -p "$data/usr/sbin" "$data/etc/init.d"
	cp "$binary" "$data/usr/sbin/netflix-pbrd"
	cp packaging/openwrt/netflix-pbrd.init "$data/etc/init.d/netflix-pbrd"
	apk mkpkg --files "$data" \
		--info "name:netflix-pbrd" \
		--info "version:$version" \
		--info "arch:$arch" \
		--info "origin:netflix-pbrd" \
		--info "maintainer:netflix-pbrd contributors" \
		--info "license:MIT" \
		--info "description:DNS-learned Netflix policy-based routing daemon" \
		--output "$output/netflix-pbrd-${version}-${arch}.apk"
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
