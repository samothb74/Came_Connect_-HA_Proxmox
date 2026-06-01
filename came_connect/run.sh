#!/usr/bin/with-contenv bashio

export CLIENT_ID="$(bashio::config 'client_id')"
export CLIENT_SECRET="$(bashio::config 'client_secret')"
export USERNAME="$(bashio::config 'username')"
export PASSWORD="$(bashio::config 'password')"
export DEVICE_ID="$(bashio::config 'device_id')"

if [ -z "$CLIENT_ID" ] || [ -z "$CLIENT_SECRET" ] || [ -z "$USERNAME" ] || [ -z "$PASSWORD" ] || [ -z "$DEVICE_ID" ]; then
  bashio::log.fatal "Missing required configuration values."
  exit 1
fi

cd /app
set -e

exec /opt/venv/bin/python -m uvicorn main:app --host 0.0.0.0 --port 8099
