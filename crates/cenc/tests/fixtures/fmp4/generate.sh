#!/usr/bin/env bash
set -euo pipefail

OUTPUT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="$(mktemp -d)"

cleanup() {
  rm -rf "${WORK_DIR}"
}
trap cleanup EXIT

PLAINTEXT_MP4="${WORK_DIR}/plain.mp4"
FRAG_MP4="${WORK_DIR}/plain.frag.mp4"

KID="00112233445566778899aabbccddeeff"
KEY="0123456789abcdef0123456789abcdef"
IV="0001020304050607"

ffmpeg -f lavfi -i sine=frequency=1000:duration=1 \
  -c:a aac -b:a 96k -movflags +faststart \
  -y "${PLAINTEXT_MP4}"

mp4fragment "${PLAINTEXT_MP4}" "${FRAG_MP4}"

cp "${FRAG_MP4}" "${OUTPUT_DIR}/plain.mp4"

mp4encrypt --method MPEG-CENC \
  --key "1:${KEY}:${IV}" --property "1:KID:${KID}" \
  "${FRAG_MP4}" "${OUTPUT_DIR}/cenc.mp4"

mp4encrypt --method MPEG-CENS \
  --key "1:${KEY}:${IV}" --property "1:KID:${KID}" \
  "${FRAG_MP4}" "${OUTPUT_DIR}/cens.mp4"

mp4encrypt --method MPEG-CBC1 \
  --key "1:${KEY}:${IV}" --property "1:KID:${KID}" \
  "${FRAG_MP4}" "${OUTPUT_DIR}/cbc1.mp4"

mp4encrypt --method MPEG-CBCS \
  --key "1:${KEY}:${IV}" --property "1:KID:${KID}" \
  "${FRAG_MP4}" "${OUTPUT_DIR}/cbcs.mp4"
