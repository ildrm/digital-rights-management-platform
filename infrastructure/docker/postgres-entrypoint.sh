#!/bin/sh
set -eu
install -d -m 0700 -o postgres -g postgres /var/lib/postgresql/tls
install -m 0600 -o postgres -g postgres /run/secrets/server-key /var/lib/postgresql/tls/server.key
install -m 0644 -o postgres -g postgres /run/secrets/server-cert /var/lib/postgresql/tls/server.crt
exec /usr/local/bin/docker-entrypoint.sh postgres \
  -c ssl=on \
  -c ssl_cert_file=/var/lib/postgresql/tls/server.crt \
  -c ssl_key_file=/var/lib/postgresql/tls/server.key \
  -c password_encryption=scram-sha-256
