#!/usr/bin/env bash
# Fetch Abbott's SecureKeyBox native libraries for the experimental Lingo build
# from the PRIVATE jwoglom/lingo-apk repository and drop them into the libre3
# flavor's jniLibs. These are Abbott's proprietary white-box libraries; they are
# NOT part of this repository and are never committed here. This script only runs
# when a token with read access to the private repo is available, so ordinary
# builds (and forks) are unaffected.
#
# Environment:
#   LINGO_SKB_TOKEN   GitHub token with read access to jwoglom/lingo-apk
#                     (in CI, provide it as a repository secret of the same name).
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

for pair in "${libs[@]}"; do
	src=${pair%%=*}
	out=${pair##*=}
	echo "fetch-lingo-skb: $repo/$src -> jniLibs/arm64-v8a/$out"
	# The contents API with the raw media type streams the file content directly
	# (works for the large white-box libraries; the JSON API would base64 them).
	code=$(curl -sS -w '%{http_code}' -o "$dest/$out" \
		-H "Authorization: Bearer $token" \
		-H "Accept: application/vnd.github.raw+json" \
		-H "X-GitHub-Api-Version: 2022-11-28" \
		"$api/$src$refq")
	if [ "$code" != "200" ]; then
		echo "fetch-lingo-skb: FAILED to fetch $src (HTTP $code)" >&2
		# Show a short diagnostic (the body on error is small JSON).
		head -c 300 "$dest/$out" >&2 || true; echo >&2
		rm -f "$dest/$out"
		exit 1
	fi
done

echo "fetch-lingo-skb: fetched $(ls "$dest"/*.so | wc -l | tr -d ' ') libraries into $dest"
ls -l "$dest"
