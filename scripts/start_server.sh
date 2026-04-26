#!/usr/bin/env bash
set -euxo pipefail
# Ensure Nginx Config is Set
scripts/install-nginx-config.sh

# Checking MySQL TCP connection
scripts/wait-for-it.sh --timeout=60 $MYSQL_HOST:$MYSQL_PORT

# Start Server using uv run (no need to manually activate venv)
export QUART_ENV=development
export QUART_DEBUG=0
# Python for Dev
# Hypercorn for Prod
# `exec` so Python becomes PID 1 and receives SIGTERM directly on stop.
exec uv run python main.py
#exec hypercorn main.py
