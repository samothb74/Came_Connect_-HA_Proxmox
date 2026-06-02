#!/usr/bin/with-contenv bashio
set -e

export CAME_CONNECT_CLIENT_ID="$(bashio::config 'client_id')"
export CAME_CONNECT_CLIENT_SECRET="$(bashio::config 'client_secret')"
export CAME_CONNECT_USERNAME="$(bashio::config 'username')"
export CAME_CONNECT_PASSWORD="$(bashio::config 'password')"
export CAME_CONNECT_DEVICE_ID="$(bashio::config 'device_id')"
export PUBLIC_BASE_URL="$(bashio::config 'public_base_url')"

bashio::log.info "CLIENT_ID set: $( [ -n "$CAME_CONNECT_CLIENT_ID" ] && echo yes || echo no )"
bashio::log.info "CLIENT_SECRET set: $( [ -n "$CAME_CONNECT_CLIENT_SECRET" ] && echo yes || echo no )"
bashio::log.info "USERNAME set: $( [ -n "$CAME_CONNECT_USERNAME" ] && echo yes || echo no )"
bashio::log.info "PASSWORD set: $( [ -n "$CAME_CONNECT_PASSWORD" ] && echo yes || echo no )"
bashio::log.info "DEVICE_ID set: $( [ -n "$CAME_CONNECT_DEVICE_ID" ] && echo yes || echo no )"

cd /app
export PYTHONPATH=/app

python3 -m py_compile /app/main.py
exec uvicorn app.main:app --host 0.0.0.0 --port 9002
