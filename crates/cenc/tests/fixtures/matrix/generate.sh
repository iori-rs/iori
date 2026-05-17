#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/generated"
SOURCE_DIR="${OUTPUT_DIR}/sources"
PLAIN_DIR="${OUTPUT_DIR}/plain"
ENCRYPTED_DIR="${OUTPUT_DIR}/encrypted"
ORACLE_DIR="${OUTPUT_DIR}/oracle"

VIDEO_KID="00112233445566778899aabbccddeeff"
VIDEO_KEY="0123456789abcdef0123456789abcdef"
AUDIO_KID="ffeeddccbbaa99887766554433221100"
AUDIO_KEY="fedcba9876543210fedcba9876543210"
IV="0001020304050607"

require_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required tool: $1" >&2
    exit 1
  fi
}

make_audio() {
  local name="$1"
  local duration="$2"
  local output="${SOURCE_DIR}/${name}.mp4"
  ffmpeg -hide_banner -loglevel error \
    -f lavfi -i "sine=frequency=1000:duration=${duration}" \
    -c:a aac -b:a 96k -movflags +faststart \
    -y "${output}"
}

make_video() {
  local name="$1"
  local duration="$2"
  local size="$3"
  local output="${SOURCE_DIR}/${name}.mp4"
  ffmpeg -hide_banner -loglevel error \
    -f lavfi -i "testsrc2=size=${size}:rate=30:duration=${duration}" \
    -c:v libx264 -pix_fmt yuv420p -profile:v baseline \
    -g 30 -keyint_min 30 -sc_threshold 0 -movflags +faststart \
    -y "${output}"
}

make_av() {
  local name="$1"
  local video_source="$2"
  local audio_source="$3"
  local output="${SOURCE_DIR}/${name}.mp4"
  ffmpeg -hide_banner -loglevel error \
    -i "${video_source}" -i "${audio_source}" \
    -map 0:v:0 -map 1:a:0 -c copy -movflags +faststart \
    -y "${output}"
}

fragment() {
  local name="$1"
  mp4fragment "${SOURCE_DIR}/${name}.mp4" "${PLAIN_DIR}/${name}.mp4"
}

method_suffix() {
  local method="$1"
  echo "${method#MPEG-}" | tr '[:upper:]' '[:lower:]'
}

encrypt_audio_track() {
  local name="$1"
  local method="$2"
  local suffix
  suffix="$(method_suffix "${method}")"
  mp4encrypt --method "${method}" \
    --key "1:${AUDIO_KEY}:${IV}" --property "1:KID:${AUDIO_KID}" \
    "${PLAIN_DIR}/${name}.mp4" "${ENCRYPTED_DIR}/${name}.${suffix}.mp4"
}

encrypt_video_track() {
  local name="$1"
  local method="$2"
  local suffix
  suffix="$(method_suffix "${method}")"
  mp4encrypt --method "${method}" \
    --key "1:${VIDEO_KEY}:${IV}" --property "1:KID:${VIDEO_KID}" \
    "${PLAIN_DIR}/${name}.mp4" "${ENCRYPTED_DIR}/${name}.${suffix}.mp4"
}

encrypt_av_tracks() {
  local name="$1"
  local method="$2"
  local suffix
  suffix="$(method_suffix "${method}")"
  mp4encrypt --method "${method}" \
    --key "1:${VIDEO_KEY}:${IV}" --property "1:KID:${VIDEO_KID}" \
    --key "2:${AUDIO_KEY}:${IV}" --property "2:KID:${AUDIO_KID}" \
    "${PLAIN_DIR}/${name}.mp4" "${ENCRYPTED_DIR}/${name}.${suffix}.mp4"
}

decrypt_oracle() {
  local name="$1"
  local method="$2"
  local suffix
  suffix="$(method_suffix "${method}")"
  mp4decrypt \
    --key "${VIDEO_KID}:${VIDEO_KEY}" \
    --key "${AUDIO_KID}:${AUDIO_KEY}" \
    "${ENCRYPTED_DIR}/${name}.${suffix}.mp4" "${ORACLE_DIR}/${name}.${suffix}.dec.mp4"
}

write_manifest_entry() {
  local name="$1"
  local kind="$2"
  local method="$3"
  local suffix
  suffix="$(method_suffix "${method}")"
  printf "%s\t%s\t%s\t%s\t%s\n" \
    "${name}" \
    "${kind}" \
    "${method}" \
    "encrypted/${name}.${suffix}.mp4" \
    "oracle/${name}.${suffix}.dec.mp4" >>"${OUTPUT_DIR}/manifest.tsv"
}

for tool in ffmpeg mp4fragment mp4encrypt mp4decrypt; do
  require_tool "${tool}"
done

rm -rf "${OUTPUT_DIR}"
mkdir -p "${SOURCE_DIR}" "${PLAIN_DIR}" "${ENCRYPTED_DIR}" "${ORACLE_DIR}"
printf "name\tkind\tmethod\tencrypted\toracle\n" >"${OUTPUT_DIR}/manifest.tsv"

make_audio "audio_1s" 1
make_audio "audio_4s" 4
make_video "video_180p_1s" 1 "320x180"
make_video "video_360p_4s" 4 "640x360"
make_av "av_180p_1s" "${SOURCE_DIR}/video_180p_1s.mp4" "${SOURCE_DIR}/audio_1s.mp4"
make_av "av_360p_4s" "${SOURCE_DIR}/video_360p_4s.mp4" "${SOURCE_DIR}/audio_4s.mp4"

for name in audio_1s audio_4s video_180p_1s video_360p_4s av_180p_1s av_360p_4s; do
  fragment "${name}"
done

for method in MPEG-CENC MPEG-CENS MPEG-CBC1 MPEG-CBCS; do
  for name in audio_1s audio_4s; do
    encrypt_audio_track "${name}" "${method}"
    decrypt_oracle "${name}" "${method}"
    write_manifest_entry "${name}" "audio" "${method}"
  done

  for name in video_180p_1s video_360p_4s; do
    encrypt_video_track "${name}" "${method}"
    decrypt_oracle "${name}" "${method}"
    write_manifest_entry "${name}" "video" "${method}"
  done

  for name in av_180p_1s av_360p_4s; do
    encrypt_av_tracks "${name}" "${method}"
    decrypt_oracle "${name}" "${method}"
    write_manifest_entry "${name}" "audio-video" "${method}"
  done
done

echo "generated encryption matrix at ${OUTPUT_DIR}"
