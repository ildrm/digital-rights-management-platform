#!/usr/bin/env bash
# Disposable full integration gate. Requires local PostgreSQL tools and Docker.
set -euo pipefail
cd "$(dirname "$0")/.."
test_root=$(mktemp -d /tmp/drm-verify.XXXXXX)
bao_name="drm-verify-bao-$$"
s3_name="drm-verify-s3-$$"
cleanup() {
  docker rm -f "$bao_name" "$s3_name" >/dev/null 2>&1 || true
  pg_ctl -D "$test_root/data" stop -m immediate >/dev/null 2>&1 || true
  rm -rf "$test_root"
}
trap cleanup EXIT
unset MIGRATION_DATABASE_URL MIGRATION_DATABASE_CA_FILE PGSSLMODE PGPASSWORD PGOPTIONS
export PGHOST="$test_root" PGPORT=55432 PGUSER=drm_migrator PGDATABASE=drm_test_local
initdb -D "$test_root/data" -U drm_migrator -A trust --no-instructions >"$test_root/init.log"
pg_ctl -D "$test_root/data" -o "-k $test_root -h '' -p 55432" -l "$test_root/postgres.log" start
createdb "$PGDATABASE"
npm run migrate
npm run migrate
psql -v ON_ERROR_STOP=1 -f tests/postgres/core.sql
psql -v ON_ERROR_STOP=1 -f infrastructure/postgres/provision-runtime.sql
psql -v ON_ERROR_STOP=1 -c "CREATE ROLE drm_app_test LOGIN; GRANT USAGE ON SCHEMA drm TO drm_app_test; GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA drm TO drm_app_test"
psql -v ON_ERROR_STOP=1 -c "CREATE ROLE drm_api_test LOGIN; GRANT drm_runtime_api TO drm_api_test; CREATE ROLE drm_worker_test LOGIN; GRANT drm_runtime_worker TO drm_worker_test"
docker run -d --rm --name "$bao_name" -p 127.0.0.1::8200 --entrypoint bao ghcr.io/openbao/openbao:2.7.0@sha256:71156a1c6623a5fa3f5e61b0c6a8ead0faf0df29a778339188443551995d1315 server -dev -dev-root-token-id=dev-only-token -dev-listen-address=0.0.0.0:8200 >/dev/null
docker run -d --rm --name "$s3_name" -p 127.0.0.1::8333 -v "$PWD/infrastructure/test/seaweedfs-s3.json:/etc/seaweedfs/s3.json:ro" --entrypoint weed ghcr.io/chrislusf/seaweedfs:4.47@sha256:ce9e796f1fe6f06968f4c04bdaf8f678dad9c8acdfef3d244133d71bfa6bf882 mini -dir=/data -bucket=drm-private-packages -s3.config=/etc/seaweedfs/s3.json >/dev/null
export BAO_TEST_URL="http://$(docker port "$bao_name" 8200/tcp)/"
export S3_TEST_URL="http://$(docker port "$s3_name" 8333/tcp)/"
for attempt in {1..30}; do
  if curl -fsS "${BAO_TEST_URL}v1/sys/health" >/dev/null 2>&1 && curl -sS "$S3_TEST_URL" >/dev/null 2>&1; then break; fi
  sleep 1
done
curl -fsS -X POST -H 'X-Vault-Token: dev-only-token' -H 'Content-Type: application/json' -d '{"type":"transit"}' "${BAO_TEST_URL}v1/sys/mounts/transit" >/dev/null
curl -fsS -X POST -H 'X-Vault-Token: dev-only-token' -H 'Content-Type: application/json' -d '{"type":"ed25519","exportable":false}' "${BAO_TEST_URL}v1/transit/keys/license-sign" >/dev/null
curl -fsS -X POST -H 'X-Vault-Token: dev-only-token' -H 'Content-Type: application/json' -d '{"type":"aes256-gcm96","derived":true,"exportable":false}' "${BAO_TEST_URL}v1/transit/keys/tenant-key" >/dev/null
export PG_TEST=1 API_TEST=1 BAO_TEST=1 S3_TEST=1 SELFHOST_TEST=1
export PG_TEST_HOST="$PGHOST" PG_TEST_PORT="$PGPORT" PG_TEST_DATABASE="$PGDATABASE" PG_TEST_USER=drm_app_test
export PG_RUNTIME_TEST_USER=drm_api_test PG_WORKER_TEST_USER=drm_worker_test
export BAO_TEST_TOKEN=dev-only-token S3_TEST_ACCESS=dev-access S3_TEST_SECRET=dev-secret-only-for-loopback
npm run typecheck
npm test
