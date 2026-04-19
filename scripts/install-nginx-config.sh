#!/usr/bin/env bash
set -euo pipefail

echo "Sourcing environment from .env file"
while IFS= read -r line || [[ -n "$line" ]]; do
  if [[ "$line" =~ ^[[:space:]]*# || -z "$line" ]]; then
    continue
  fi
  key="${line%%=*}"
  value="${line#*=}"
  export "$key"="$value"
done < .env

echo "Installing nginx configuration"
sed -e "s|\${APP_PORT}|$APP_PORT|g" \
    -e "s|\${DOMAIN}|$DOMAIN|g" \
    -e "s|\${GULAG_ADDRESS}|$GULAG_ADDRESS|g" \
    -e "s|\${GULAG_PORT}|$GULAG_PORT|g" \
    -e "s|\${SSL_CERT_PATH}|$SSL_CERT_PATH|g" \
    -e "s|\${SSL_KEY_PATH}|$SSL_KEY_PATH|g" \
    ext/nginx.conf.example > /etc/nginx/sites-available/web.conf

ln -f -s /etc/nginx/sites-available/web.conf /etc/nginx/sites-enabled/web.conf

echo "Restarting nginx"
if service nginx restart; then
    echo "Nginx restarted successfully"
else
    echo "Failed to restart nginx. Status:"
    nginx
fi


echo "Nginx configuration installed"
