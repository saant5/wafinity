#!/usr/bin/env bash
set -e

mkdir -p logs

python vendor_backend.py &
exec gunicorn -w 2 -b 0.0.0.0:${PORT:-5000} gateway:app