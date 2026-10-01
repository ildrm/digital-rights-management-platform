# Standalone encrypted backup and recovery

Archives contain a consistent PostgreSQL custom-format dump and twelve explicitly selected recovery files: database passwords/TLS material and local wrapping, license, and authentication keys. Package ciphertext, catalog, grants, orders, journals, and audit history are in PostgreSQL. Optional external stores/providers and application software images are outside this format.

## Scheduled Docker backups

Generate a long random passphrase in a mode-0600 file. Keep an independent secure copy off-host; it is not in the archive.

```sh
mkdir -p .secrets/backups
node --input-type=module -e 'import {randomBytes} from "node:crypto"; import {writeFileSync} from "node:fs"; writeFileSync(".secrets/backup-passphrase",randomBytes(48).toString("base64url")+"\n",{mode:0o600,flag:"wx"});'
docker compose -f compose.standalone.yaml --profile backup up --build -d backup
docker compose -f compose.standalone.yaml --profile backup logs backup
```

The Docker job uses pinned Node 24 LTS and PostgreSQL 18 tools, verified database TLS, a read-only root filesystem, and tmpfs. It has no published port or Docker socket. Its recovery-secret mount and privileged backup credentials require operator-level protection. Defaults: run immediately, repeat every 24 hours, retain 14 scheduler archives, retry failures after five minutes. Retention removes only scheduler-named regular files after a successful backup. Stale success makes the service unhealthy; alert delivery and off-host copying remain deployment work.

Override `DRM_BACKUP_DIR`, `DRM_BACKUP_PASSPHRASE_FILE`, `BACKUP_INTERVAL_SECONDS` (3600–604800), and `BACKUP_RETAIN_COUNT` (2–365). Daily snapshots do not satisfy a five-minute RPO; continuous WAL archiving and off-host replication remain required for that objective.

Manual operator backup:

```sh
BACKUP_PASSPHRASE_FILE=.secrets/backup-passphrase npm run backup:standalone -- create .secrets/backups/manual.drmbackup .secrets/standalone
```

AES-256-GCM authenticates the full stream and header; scrypt derives the key from the private passphrase with fresh salt/nonce. Dumps stream directly into encryption. Files are mode 0600, flushed before publication, and never overwrite an archive. Interrupted jobs may leave unpublished encrypted `.partial` files. Copy completed archives off-host, verify their SHA-256, and retain the matching release and pinned Docker images. Coordinate key/certificate changes with backup retention.

## Isolated restore

Use a fresh Compose project, new secret directory and database volume, and a free loopback port. Start only PostgreSQL before restoring; do not migrate the empty database first.

```sh
BACKUP_PASSPHRASE_FILE=.secrets/backup-passphrase npm run backup:standalone -- extract .secrets/backups/manual.drmbackup .secrets/recovery
export DRM_SECRET_DIR="$PWD/.secrets/recovery"
export DRM_API_PORT=8081
export COMPOSE_PROJECT_NAME=drm-recovery
docker compose -f compose.standalone.yaml up -d --wait postgres
docker compose -f compose.standalone.yaml exec -T postgres pg_restore --exit-on-error --single-transaction --no-owner --no-acl -U postgres -d drm < .secrets/recovery/database.dump
docker compose -f compose.standalone.yaml up --build -d --wait api
```

Extraction authenticates into a private temporary file before exposing recovered files. Wrong keys, tampering, substituted secret paths, and existing destinations fail. After restore, the migration job checks checksums and recreates scoped runtime logins/grants. Never restore into the source database.

With a pre-backup administration smoke report, verify recovered authentication, library, device enrollment, license, package, manifest, key unwrap, and content checksum:

```sh
node --experimental-strip-types scripts/verify-standalone-content.ts .secrets/standalone/smoke-admin.json .secrets/recovery http://127.0.0.1:8081
```

This operator check uses recovered keys; it is not a protected customer client. Record evidence, then stop the drill with `docker compose -f compose.standalone.yaml down`. Protect extracted secrets/plaintext dumps and apply retention. Unset `DRM_SECRET_DIR`, `DRM_API_PORT`, and `COMPOSE_PROJECT_NAME` after the drill, or use a separate operator shell. Production qualification still requires separate-host recovery from off-host media, measured outage RPO/RTO, failover/fencing, software-image recovery, and key-rotation/loss drills.
