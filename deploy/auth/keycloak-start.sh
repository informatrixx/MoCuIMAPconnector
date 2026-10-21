#!/bin/bash
set -euo pipefail
# Never enable shell tracing: these values are expanded only in the provider process.
read -r KC_DB_PASSWORD < /run/secrets/provider_db
read -r MOCU_CHATGPT_SECRET < /run/secrets/chatgpt_client
read -r MOCU_ADMIN_SECRET < /run/secrets/admin_client
export KC_DB_PASSWORD MOCU_CHATGPT_SECRET MOCU_ADMIN_SECRET
if [[ -f /run/secrets/initial_user ]]; then
    read -r MOCU_INITIAL_USER_PASSWORD < /run/secrets/initial_user
    export MOCU_INITIAL_USER_PASSWORD
fi
exec /opt/keycloak/bin/kc.sh start --optimized --import-realm
