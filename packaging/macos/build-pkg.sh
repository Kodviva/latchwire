#!/bin/sh
# Builds the macOS installer, unsigned, from a finished binary:
#
#   packaging/macos/build-pkg.sh --binary dist/macos/latchwire \
#       --licenses dist/macos/THIRD_PARTY_LICENSES.txt \
#       [--app dist/macos/Latchwire.app] --out dist/macos/latchwire.pkg
#
# For a release, sign the binary first (sign-binary.sh): the package carries
# what it is given. --app adds a desktop application bundle to /Applications
# (Plan 3), which is optional.
#
# Files, once installed:
#   /usr/local/latchwire/bin/latchwire     the program. Not in /usr/local/bin:
#                                          the daemon runs it as root, and
#                                          Intel Homebrew gives that directory
#                                          to a user. postinstall links it.
#   /usr/local/latchwire/lifecycle.sh      upgrade and removal
#   /usr/local/latchwire/share/            licences
#   /Library/LaunchDaemons, LaunchAgents   the launchd jobs
#   /etc/newsyslog.d                       log rotation (/private/etc in the
#                                          payload: /etc is a symbolic link)
set -eu

die() { echo "build-pkg.sh: $*" >&2; exit 1; }

binary='' licenses='' app='' out=''
while [ $# -gt 0 ]; do
	case $1 in
	--binary) binary=${2:?}; shift 2 ;;
	--licenses) licenses=${2:?}; shift 2 ;;
	--app) app=${2:?}; shift 2 ;;
	--out) out=${2:?}; shift 2 ;;
	*) die "unknown argument: $1" ;;
	esac
done
[ -f "$binary" ] || die "--binary: no such file: $binary"
[ -f "$licenses" ] || die "--licenses: no such file: $licenses"
[ -n "$out" ] || die "--out is required"
[ -z "$app" ] || [ -d "$app" ] || die "--app: no such directory: $app"

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
# shellcheck source=packaging/toolchain.env
. "$root/packaging/toolchain.env"
version=${LATCHWIRE_VERSION:-$(sh "$root/packaging/version.sh")}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
stage=$work/root
umask 022

mkdir -p "$stage/usr/local/latchwire/bin" "$stage/usr/local/latchwire/share" \
	"$stage/Library/LaunchDaemons" "$stage/Library/LaunchAgents" "$stage/private/etc/newsyslog.d"
install -m 0755 "$binary" "$stage/usr/local/latchwire/bin/latchwire"
install -m 0755 "$here/lifecycle.sh" "$stage/usr/local/latchwire/lifecycle.sh"
install -m 0644 "$root/LICENSE" "$licenses" "$stage/usr/local/latchwire/share/"
# Install-time path of the binary, see the list above.
stage_plist() { # stage_plist NAME DESTINATION
	sed 's|/usr/local/bin/latchwire|/usr/local/latchwire/bin/latchwire|' "$here/$1" >"$stage/Library/$2/$1"
	chmod 0644 "$stage/Library/$2/$1"
}
stage_plist com.latchwire.daemon.plist LaunchDaemons
stage_plist com.latchwire.agent.plist LaunchAgents
install -m 0644 "$here/newsyslog.conf" "$stage/private/etc/newsyslog.d/com.latchwire.daemon.conf"

component_plist=
if [ -n "$app" ]; then
	mkdir -p "$stage/Applications"
	cp -R "$app" "$stage/Applications/"
	# The installer must not follow a moved copy of the application.
	component_plist=$work/component.plist
	cat >"$component_plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<array>
	<dict>
		<key>RootRelativeBundlePath</key>
		<string>Applications/$(basename "$app")</string>
		<key>BundleIsRelocatable</key>
		<false/>
		<key>BundleIsVersionChecked</key>
		<true/>
		<key>BundleHasStrictIdentifier</key>
		<true/>
		<key>BundleOverwriteAction</key>
		<string>upgrade</string>
	</dict>
</array>
</plist>
PLIST
fi

scripts=$work/scripts
mkdir -p "$scripts"
install -m 0755 "$here/scripts/postinstall" "$scripts/postinstall"

pkgbuild --quiet --root "$stage" --scripts "$scripts" --identifier com.latchwire.pkg \
	--version "$version" --install-location / --ownership recommended \
	${component_plist:+--component-plist "$component_plist"} \
	"$work/component.pkg"

# A shell started from an application gives every new file the attribute
# com.apple.provenance, which it cannot clear, and pkgbuild stores attributes
# as ._ files in the payload (printing "write: Permission denied" meanwhile,
# which is harmless). Rebuild the payload and its list without them.
export COPYFILE_DISABLE=1
pkgutil --expand "$work/component.pkg" "$work/expanded"
(cd "$stage" && find . | cpio -o --quiet --format odc -R 0:0) | gzip -9n >"$work/expanded/Payload"
lsbom "$work/expanded/Bom" | grep -v '/\._' >"$work/filelist"
mkbom -i "$work/filelist" "$work/expanded/Bom"
files=$(wc -l <"$work/filelist" | tr -d ' ')
sed -i '' -E "s/numberOfFiles=\"[0-9]+\"/numberOfFiles=\"$files\"/" "$work/expanded/PackageInfo"
pkgutil --flatten "$work/expanded" "$work/latchwire-component.pkg"

sed -e "s/@VERSION@/$version/" -e "s/@MIN_MACOS@/$MACOSX_DEPLOYMENT_TARGET/" \
	"$here/distribution.xml.in" >"$work/distribution.xml"
mkdir -p "$(dirname "$out")"
productbuild --quiet --distribution "$work/distribution.xml" --package-path "$work" "$out"
