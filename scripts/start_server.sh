#!/usr/bin/env bash
set -euxo pipefail
# Ensure Nginx Config is Set
scripts/install-nginx-config.sh

# Checking MySQL TCP connection
scripts/wait-for-it.sh --timeout=60 $MYSQL_HOST:$MYSQL_PORT

# Start Server
export QUART_ENV=development
export QUART_DEBUG=0
# Python for Dev
# Hypercorn for Prod
python3.11 main.py
#hypercorn main.py
