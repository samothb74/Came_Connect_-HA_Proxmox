#!/usr/bin/with-contenv bashio

export CAME_CONNECT_CLIENT_ID="$(bashio::config 'client_id')"
export CAME_CONNECT_CLIENT_SECRET="$(bashio::config 'client_secret')"
export CAME_CONNECT_USERNAME="$(bashio::config 'username')"
export CAME_CONNECT_PASSWORD="$(bashio::config 'password')"
export CAME_CONNECT_DEVICE_ID="$(bashio::config 'device_id')"

bashio::log.info "CLIENT_ID set: $([ -n "$CLIENT_ID" ] && echo yes || echo no)"
bashio::log.info "CLIENT_SECRET set: $([ -n "$CLIENT_SECRET" ] && echo yes || echo no)"
bashio::log.info "USERNAME set: $([ -n "$USERNAME" ] && echo yes || echo no)"
bashio::log.info "PASSWORD set: $([ -n "$PASSWORD" ] && echo yes || echo no)"
bashio::log.info "DEVICE_ID set: $([ -n "$DEVICE_ID" ] && echo yes || echo no)"
if [ -z "$CAME_CONNECT_CLIENT_ID" ] || [ -z "$CAME_CONNECT_CLIENT_SECRET" ] || [ -z "$CAME_CONNECT_USERNAME" ] || [ -z "$CAME_CONNECT_PASSWORD" ] || [ -z "$CAME_CONNECT_DEVICE_ID" ]; then
  bashio::log.fatal "Missing required configuration values."
  exit 1
fi

set -e
cd /app
export PYTHONPATH=/app

bashio::log.info "CLIENT_ID set: $([ -n "$CAME_CONNECT_CLIENT_ID" ] && echo yes || echo no)"
bashio::log.info "CLIENT_SECRET set: $([ -n "$CAME_CONNECT_CLIENT_SECRET" ] && echo yes || echo no)"
bashio::log.info "USERNAME set: $([ -n "$CAME_CONNECT_USERNAME" ] && echo yes || echo no)"
bashio::log.info "PASSWORD set: $([ -n "$CAME_CONNECT_PASSWORD" ] && echo yes || echo no)"
bashio::log.info "DEVICE_ID set: $([ -n "$CAME_CONNECT_DEVICE_ID" ] && echo yes || echo no)"

exec /opt/venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 9002


