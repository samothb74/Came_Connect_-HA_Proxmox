#!/usr/bin/with-contenv bashio

export CLIENT_ID="$(bashio::config 'client_id')"
export CLIENT_SECRET="$(bashio::config 'client_secret')"
export USERNAME="$(bashio::config 'username')"
export PASSWORD="$(bashio::config 'password')"
export DEVICE_ID="$(bashio::config 'device_id')"
bashio::log.info "CLIENT_ID set: $([ -n "$CLIENT_ID" ] && echo yes || echo no)"
bashio::log.info "CLIENT_SECRET set: $([ -n "$CLIENT_SECRET" ] && echo yes || echo no)"
bashio::log.info "USERNAME set: $([ -n "$USERNAME" ] && echo yes || echo no)"
bashio::log.info "PASSWORD set: $([ -n "$PASSWORD" ] && echo yes || echo no)"
bashio::log.info "DEVICE_ID set: $([ -n "$DEVICE_ID" ] && echo yes || echo no)"
if [ -z "$CLIENT_ID" ] || [ -z "$CLIENT_SECRET" ] || [ -z "$USERNAME" ] || [ -z "$PASSWORD" ] || [ -z "$DEVICE_ID" ]; then
  bashio::log.fatal "Missing required configuration values."
  exit 1
fi

set -e

cd /app
export PYTHONPATH=/app

echo "PWD=$(pwd)"
echo "Listing /app:"
ls -la /app
echo "Listing /app/app:"
ls -la /app/app

exec /opt/venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 9002


