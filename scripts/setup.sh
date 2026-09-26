#!/usr/bin/env bash
# Provision the environment.
#
# Two modes, chosen automatically:
#   external  - the Segate.Y drive is mounted. Creates an APFS disk image on it
#               and puts the venv, HF cache and FAISS index inside. Use this when
#               the internal disk is tight.
#   local     - no external drive. Everything lives in the project directory.
#
# Force one with:  MODE=local ./scripts/setup.sh
#
# The external drive is ExFAT, which has no symlinks and no POSIX exec bits, so
# a venv cannot sit on it directly - hence the disk image rather than a plain
# directory. The image also survives unplugging without corrupting the venv,
# though anything running at the time will die.
set -euo pipefail

PROJECT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXTERNAL="/Volumes/Segate.Y"
IMAGE_DIR="$EXTERNAL/COE444"
IMAGE="$IMAGE_DIR/coe444.sparsebundle"
MOUNT="/Volumes/COE444"
PY="${PY:-/opt/homebrew/bin/python3.11}"

MODE="${MODE:-auto}"
if [ "$MODE" = "auto" ]; then
  if [ -d "$EXTERNAL" ]; then MODE=external; else MODE=local; fi
fi

if [ "$MODE" = "external" ]; then
  [ -d "$EXTERNAL" ] || { echo "ERROR: $EXTERNAL not mounted." >&2; exit 1; }
  if [ ! -d "$IMAGE" ]; then
    echo "Creating 20 GB APFS sparse image at $IMAGE"
    mkdir -p "$IMAGE_DIR"
    hdiutil create -size 20g -fs APFS -type SPARSEBUNDLE -volname COE444 "$IMAGE_DIR/coe444"
  fi
  [ -d "$MOUNT" ] || hdiutil attach "$IMAGE" -mountpoint "$MOUNT"
  ROOT="$MOUNT"
else
  ROOT="$PROJECT"
fi

VENV="$ROOT/.venv"
[ "$MODE" = "external" ] && VENV="$MOUNT/venv"
HF="$ROOT/.hf-cache"
DATA="$ROOT/.data"

mkdir -p "$HF" "$DATA"
[ -d "$VENV" ] || "$PY" -m venv "$VENV"

# --no-cache-dir because pip's download cache lands on the internal disk either way.
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --no-cache-dir --quiet -r "$PROJECT/requirements.txt"

if [ ! -f "$PROJECT/.env" ]; then
  cp "$PROJECT/.env.example" "$PROJECT/.env"
  echo "Created .env - add your GROQ_API_KEY and CEREBRAS_API_KEY"
fi

# activate.sh is what you source each session; it knows which mode was set up.
cat > "$PROJECT/scripts/activate.sh" <<EOF
# source scripts/activate.sh
export HF_HOME="$HF"
export COE444_DATA_ROOT="$DATA"
source "$VENV/bin/activate"
EOF

cat <<EOF

Mode: $MODE
  venv  $VENV
  cache $HF
  data  $DATA

Each session:

    source scripts/activate.sh
    python cli.py index          # only needed once, or after editing documents
    python cli.py demo PI-101

EOF
