#!/bin/sh
# Optionally source a config file before starting. The Umbrel app uses this to
# inject user config/secrets (filled in post-install under the app data dir)
# without baking them into the image or into a public compose file.
ENV_FILE="${BRIDGE_ENV_FILE:-/data/bridge.env}"
if [ -f "$ENV_FILE" ]; then
  echo "Loading config from $ENV_FILE"
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
fi
exec python -u republisher.py
