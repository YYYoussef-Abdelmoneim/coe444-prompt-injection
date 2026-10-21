#!/bin/sh
# Run from any directory, using the existing environment; no installs or API calls here.
set -eu
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_dir"
export OMP_NUM_THREADS="${OMP_NUM_THREADS:-1}"
exec "$project_dir/.venv/bin/python" -B interface/app.py
