#!/bin/sh
set -e

# Fix data directory permissions for mounted volumes
if [ "$(id -u)" = "0" ]; then
    chown -R appuser:appuser /app/data 2>/dev/null || true
    exec su-exec appuser "$@"
else
    exec "$@"
fi
