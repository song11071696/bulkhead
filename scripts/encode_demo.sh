#!/usr/bin/env bash
# media/raw/*.webm + media/captions.srt -> media/bulkhead-demo.mp4 (H.264 1920x1080 30fps, soft English subtitles)
set -euo pipefail
cd "$(dirname "$0")/.."
TRIM=${TRIM:-1.6}   # drop the blank page load at the start
RAW=$(ls -t media/raw/*.webm | head -1)
python3 - "$TRIM" <<'PY'
import re, sys
trim = float(sys.argv[1])
def sh(m):
    h, mi, s, ms = map(int, m.groups())
    t = max(0.0, h * 3600 + mi * 60 + s + ms / 1000 - trim)
    return f"{int(t // 3600):02d}:{int(t % 3600 // 60):02d}:{int(t % 60):02d},{int(round((t % 1) * 1000)) % 1000:03d}"
src = open("media/captions.srt").read()
open("media/captions.en.srt", "w").write(re.sub(r"(\d+):(\d+):(\d+),(\d+)", sh, src))
PY
ffmpeg -y -hide_banner -loglevel error -ss "$TRIM" -i "$RAW" -i media/captions.en.srt \
  -map 0:v -map 1:s -c:v libx264 -preset veryfast -crf 20 -pix_fmt yuv420p -r 30 -vf "scale=1920:1080" \
  -c:s mov_text -metadata:s:s:0 language=eng -metadata title="Bulkhead demo" -movflags +faststart media/bulkhead-demo.mp4
ffprobe -v error -show_entries format=duration:stream=codec_name,width,height -of compact media/bulkhead-demo.mp4
# publish next to the GitHub Pages demo (plays in any browser) with a WebVTT copy of the captions
mkdir -p docs/media && cp media/bulkhead-demo.mp4 docs/media/
{ echo "WEBVTT"; echo; sed -E 's/([0-9]{2}:[0-9]{2}:[0-9]{2}),([0-9]{3})/\1.\2/g' media/captions.en.srt; } > docs/media/captions.en.vtt
