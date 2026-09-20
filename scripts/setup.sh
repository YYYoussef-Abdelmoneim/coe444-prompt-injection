#!/usr/bin/env bash
# Provision the environment. Heavy artefacts go on the external drive, because
# the internal disk has under 1 GB free.
#
#   ./scripts/setup.sh
set -euo pipefail

PROJECT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXTERNAL="/Volumes/Segate.Y"
IMAGE_DIR="$EXTERNAL/COE444"
IMAGE="$IMAGE_DIR/coe444.sparsebundle"
MOUNT="/Volumes/COE444"
PY="${PY:-/opt/homebrew/bin/python3.11}"

if [ ! -d "$EXTERNAL" ]; then
  echo "ERROR: external drive not mounted at $EXTERNAL. Plug it in and rerun." >&2
  exit 1
fi

# The external drive is ExFAT, which has no symlinks and no POSIX exec bits, so
# a venv cannot live on it directly. An APFS disk image stored as a file on that
# drive gives a real filesystem with 1.4 TB behind it.
if [ ! -d "$IMAGE" ]; then
  echo "Creating 20 GB APFS sparse image at $IMAGE"
  mkdir -p "$IMAGE_DIR"
  hdiutil create -size 20g -fs APFS -type SPARSEBUNDLE -volname COE444 "$IMAGE_DIR/coe444"
fi

if [ ! -d "$MOUNT" ]; then
  echo "Mounting $IMAGE"
  hdiutil attach "$IMAGE" -mountpoint "$MOUNT"
fi

mkdir -p "$MOUNT/coe444-data" "$MOUNT/hf-cache"

if [ ! -d "$MOUNT/venv" ]; then
  echo "Creating venv with $PY"
  "$PY" -m venv "$MOUNT/venv"
fi

# --no-cache-dir because pip's download cache lands on the internal disk.
"$MOUNT/venv/bin/pip" install --quiet --upgrade pip
"$MOUNT/venv/bin/pip" install --no-cache-dir -r "$PROJECT/requirements.txt"

if [ ! -f "$PROJECT/.env" ]; then
  cp "$PROJECT/.env.example" "$PROJECT/.env"
  echo "Created .env - add your ANTHROPIC_API_KEY"
fi

cat <<EOF

Done. Activate with:

    source $MOUNT/venv/bin/activate
    export HF_HOME=$MOUNT/hf-cache
    export COE444_DATA_ROOT=$MOUNT/coe444-data

Then:

    python cli.py index
    python cli.py ask "What is the leave policy?"
    python cli.py demo PI-001

If the drive was unplugged, remount with:

    hdiutil attach "$IMAGE" -mountpoint "$MOUNT"
EOF
