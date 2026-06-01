#!/usr/bin/with-contenv bashio
set -e

export CAME_CONNECT_CLIENT_ID="$(bashio::config 'client_id')"
export CAME_CONNECT_CLIENT_SECRET="$(bashio::config 'client_secret')"
export CAME_CONNECT_USERNAME="$(bashio::config 'username')"
export CAME_CONNECT_PASSWORD="$(bashio::config 'password')"
export CAME_CONNECT_DEVICE_ID="$(bashio::config 'device_id')"
export PUBLIC_BASE_URL="$(bashio::config 'public_base_url')"

if [ -z "$CAME_CONNECT_CLIENT_ID" ] || [ -z "$CAME_CONNECT_CLIENT_SECRET" ]; then
  bashio::log.fatal "Missing required OAuth client configuration: client_id/client_secret"
  exit 1
fi

if [ -z "$PUBLIC_BASE_URL" ]; then
  bashio::log.warning "public_base_url is empty, default in main.py will be used"
else
  bashio::log.info "PUBLIC_BASE_URL: ${PUBLIC_BASE_URL}"
fi

bashio::log.info "CLIENT_ID set: yes"
bashio::log.info "CLIENT_SECRET set: yes"
bashio::log.info "USERNAME set: $( [ -n "$CAME_CONNECT_USERNAME" ] && echo yes || echo no )"
bashio::log.info "PASSWORD set: $( [ -n "$CAME_CONNECT_PASSWORD" ] && echo yes || echo no )"
bashio::log.info "DEVICE_ID set: $( [ -n "$CAME_CONNECT_DEVICE_ID" ] && echo yes || echo no )"

cd /app
export PYTHONPATH=/app

exec uvicorn main:app --host 0.0.0.0 --port 9002
