#!/usr/bin/env bash
# Download a released Juggluco APK and extract the prebuilt native libraries
# that are not part of this repository into the jniLibs directories, as
# described in the BUILD section of README.md.
#
# Usage: scripts/fetch-prebuilt-libs.sh [version]
#
# Environment:
#   JUGGLUCO_LIBS_VERSION  released version to take the libraries from
#   JUGGLUCO_APK_URL       full URL of an APK, overrides the version
#   JUGGLUCO_APK_CACHE     directory to keep the downloaded APK in

set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)

version=${1:-${JUGGLUCO_LIBS_VERSION:-11.1.0}}
url=${JUGGLUCO_APK_URL:-"https://sourceforge.net/projects/juggluco/files/Juggluco-${version}.apk/download"}
cache=${JUGGLUCO_APK_CACHE:-"$root/build/prebuilt-libs"}

# libcalibrat2.so/libcalibrate.so go next to the other main-source-set libraries,
# the Sibionics libraries go in the mobileSi source set. Only the ABIs that the
# downloaded APK actually contains are filled in.
main_libs=(libcalibrat2.so libcalibrate.so)
si_libs=(
	libCALCULATION.so
	libnative-algorithm-jni-v116A.so
	libnative-algorithm-v1_1_6A.so
	libnative-sensitivity-v110.so
	libnative-algorithm-jni-v115G.so
	libnative-algorithm-v1_1_5G.so
	libnative-encrypy-decrypt-v110.so
	libnative-struct2json.so
)
main_abis=(armeabi-v7a arm64-v8a x86 x86_64)
si_abis=(armeabi-v7a arm64-v8a)

apk="$cache/Juggluco-${version}.apk"
mkdir -p "$cache"

if [ -s "$apk" ]; then
	echo "Using cached $apk"
else
	echo "Downloading $url"
	curl -fsSL --retry 4 --retry-delay 2 --retry-connrefused -o "$apk.part" "$url"
	mv "$apk.part" "$apk"
fi

if ! unzip -l "$apk" >/dev/null 2>&1; then
	echo "$apk is not a valid APK (zip) file" >&2
	exit 1
fi

extracted=0
unpack() { # unpack <destination-parent> <abi-list-name> <lib-list-name>
	local destparent=$1
	local -n abis=$2
	local -n libs=$3
	local abi lib dest

	for abi in "${abis[@]}"; do
		for lib in "${libs[@]}"; do
			unzip -l "$apk" "lib/$abi/$lib" >/dev/null 2>&1 || continue
			dest="$destparent/$abi"
			mkdir -p "$dest"
			unzip -o -q -j "$apk" "lib/$abi/$lib" -d "$dest"
			echo "  $dest/$lib"
			extracted=$((extracted + 1))
		done
	done
}

echo "Extracting native libraries from Juggluco-${version}.apk:"
unpack "$root/Common/src/main/jniLibs" main_abis main_libs
unpack "$root/Common/src/mobileSi/jniLibs" si_abis si_libs

if [ "$extracted" -eq 0 ]; then
	echo "No native libraries found in $apk" >&2
	exit 1
fi

echo "Extracted $extracted libraries."
