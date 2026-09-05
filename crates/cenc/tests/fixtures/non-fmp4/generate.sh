#!/usr/bin/env bash
set -euo pipefail

OUTPUT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ffmpeg -f lavfi -i sine=frequency=1000:duration=1 \
  -c:a aac -b:a 96k -movflags +faststart \
  -y "${OUTPUT_DIR}/plain.mp4"

# Note: Bento4 mp4encrypt only supports MPEG-CENC/CENS/CBC1/CBCS on fragmented MP4.
# Keep this directory for non-fragmented (moov+mdat) fixtures only.
