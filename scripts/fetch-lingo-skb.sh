#!/usr/bin/env bash
# Fetch Abbott's SecureKeyBox native libraries for the experimental Lingo build
# from the PRIVATE jwoglom/lingo-apk repository and drop them into the libre3
# flavor's jniLibs. These are Abbott's proprietary white-box libraries; they are
# NOT part of this repository and are never committed here. This script only runs
# when a token with read access to the private repo is available, so ordinary
# builds (and forks) are unaffected.
#
# Environment:
#   LINGO_SKB_TOKEN   GitHub token with read access to jwoglom/lingo-apk.
#                     In CI this is mapped from the repository secret
#                     LINGO_REPO_READONLY_TOKEN (see .github/workflows/build.yml).
#   LINGO_SKB_REPO    override source repo (default jwoglom/lingo-apk)
#   LINGO_SKB_REF     override git ref (default the repo's default branch)
#
# Without a token the script exits 0 without doing anything, and the build
# proceeds without the Lingo SecureKeyBox (the libre3 Lingo path is then inert).

set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
repo=${LINGO_SKB_REPO:-jwoglom/lingo-apk}
ref=${LINGO_SKB_REF:-}
token=${LINGO_SKB_TOKEN:-}

if [ -z "$token" ]; then
	echo "fetch-lingo-skb: no LINGO_SKB_TOKEN set; skipping Lingo SecureKeyBox fetch."
	exit 0
fi

# arm64-v8a only: the private repo carries the arm64 split's libraries. The Lingo
# path is therefore arm64-only for now; other ABIs build without it.
dest="$root/Common/src/libre3/jniLibs/arm64-v8a"
mkdir -p "$dest"

# Files to fetch from the source repo, as <src path in repo>=<dest filename>.
libs=(
	"_extracted_native/libgks_skbwrapper.so=libgks_skbwrapper.so"
	"_extracted_native/libSecureKeyBoxJava.so=libSecureKeyBoxJava.so"
	"_extracted_native/libgksdcm.so=libgksdcm.so"
	"_extracted_native/libc++_shared.so=libc++_shared.so"
)

api="https://api.github.com/repos/$repo/contents"
refq=""
[ -n "$ref" ] && refq="?ref=$ref"

# Download one file from the source repo via the contents API (raw media type
# streams content directly; the JSON API would base64 large files).
fetch_raw() {
	local src=$1 out=$2 code
	code=$(curl -sS -w '%{http_code}' -o "$out" \
		-H "Authorization: Bearer $token" \
		-H "Accept: application/vnd.github.raw+json" \
		-H "X-GitHub-Api-Version: 2022-11-28" \
		"$api/$src$refq")
	if [ "$code" != "200" ]; then
		echo "fetch-lingo-skb: FAILED to fetch $src (HTTP $code)" >&2
		head -c 300 "$out" >&2 || true; echo >&2
		rm -f "$out"
		return 1
	fi
}

for pair in "${libs[@]}"; do
	src=${pair%%=*}
	out=${pair##*=}
	echo "fetch-lingo-skb: $repo/$src -> jniLibs/arm64-v8a/$out"
	fetch_raw "$src" "$dest/$out"
done

echo "fetch-lingo-skb: fetched $(ls "$dest"/*.so | wc -l | tr -d ' ') libraries into $dest"
ls -l "$dest"

# --- GKS classes dex bundle -------------------------------------------------
# The SecureKeyBox natives bind to the Lingo GKS Java classes, which Juggluco
# loads at runtime through a DexClassLoader (see LingoSKB). Extract the Lingo
# APK's dex files into a jar bundled as a libre3 asset (gitignored). We ship the
# whole classes*.dex set: a DexClassLoader whose parent is Juggluco's loader
# resolves shared classes (android.*, the no-op MSLog) from the parent first, so
# only the GKS classes and their private dependencies come from this jar.
apkpath=${LINGO_SKB_APK:-com.abbott.lingo.wellness.apk}
assets="$root/Common/src/libre3/assets"
mkdir -p "$assets"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
echo "fetch-lingo-skb: $repo/$apkpath -> extracting classes*.dex"
if ! fetch_raw "$apkpath" "$work/lingo.apk"; then
	echo "fetch-lingo-skb: could not fetch $apkpath; skipping dex bundle" >&2
	exit 1
fi
( cd "$work" && unzip -o -q lingo.apk 'classes*.dex' )
ndex=$(ls "$work"/classes*.dex 2>/dev/null | wc -l | tr -d ' ')
if [ "$ndex" = "0" ]; then
	echo "fetch-lingo-skb: no classes*.dex in APK" >&2
	exit 1
fi
rm -f "$assets/lingogks.jar"
( cd "$work" && zip -q "$assets/lingogks.jar" classes*.dex )
echo "fetch-lingo-skb: bundled $ndex dex file(s) into libre3/assets/lingogks.jar"
ls -l "$assets/lingogks.jar"
