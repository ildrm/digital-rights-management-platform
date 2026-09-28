# Technology decision: self-hosted core

The active API runtime uses PostgreSQL, OpenBao Transit, and an S3-compatible object endpoint. It needs no AWS account or managed DRM vendor account for the narrow secure-viewer publishing and licensing path. The AWS KMS and Axinom packages remain optional adapters; the runtime does not import them. The release gate remains FAIL because self-hosting does not supply the missing product features or certify consumer DRM.

## OpenBao Transit

The active signer uses a non-exportable Ed25519 Transit key with a **pinned key version**. Its key ID includes that version so a rotated key cannot silently change the verification key. The content-key wrapper uses a per-tenant allowlisted, derived AES-256-GCM Transit key. Transit `context` binds the tenant, and authenticated `associated_data` binds tenant, asset, version, and rendition. The OpenBao ciphertext includes its own version for rotation. The API reads its token from a mounted file, accepts only HTTPS origins, and fails closed on unavailable or invalid Transit responses. The application token needs read access to the configured key metadata and only the specific sign/encrypt/decrypt operations; it must not be a root token. [Transit API](https://openbao.org/docs/api/secret/transit/), [Transit key types](https://openbao.org/docs/secrets/transit/).

The disposable OpenBao 2.7.0 dev-server integration test proved that Node verifies its Ed25519 signature, content keys round-trip, and changing asset identity denies decryption. Dev mode and its root token are only test fixtures. A real installation still needs TLS, unseal and recovery design, durable storage, scoped auth, audit logging, backup/restore, and incident drills. [OpenBao storage guidance](https://openbao.org/docs/configuration/storage/).

## SeaweedFS via the S3 protocol

The active object store target is SeaweedFS. The application uses the AWS SDK only as an S3 protocol client, with an explicit HTTPS endpoint and access credentials from mounted files. The package is encrypted and signed before upload, so it does not depend on AWS SSE-KMS. The adapter supplies SHA-256 upload checksum and `If-None-Match: *` conditional creation. Live SeaweedFS 4.47 tests confirmed writes, reads, checksum integrity, rejection of duplicate creation, and deletion. Production deployment still requires scoped credentials, TLS, replication, snapshots/backups, monitoring, capacity planning, and a restore exercise. [SeaweedFS releases](https://github.com/seaweedfs/seaweedfs/releases), [conditional writes](https://www.seaweedfs.com/blog/conditional-writes/).

MinIO community was rejected as the new default because its public repository was archived in April 2026 and is no longer maintained. [Archived repository notice](https://github.com/minio/minio).

## Identity, media DRM, and payments

The OIDC verifier can use a self-hosted identity provider that issues the documented `tenant_id`, `drm:license`, and `drm:publish` claims. No identity provider has been installed or tested here. Payments could start with a manually reconciled invoice workflow, but no commerce, tax, refund, payout, or ledger code exists; changing payment provider alone would not make it safe to charge users.

The generic secure-viewer package is not Widevine, FairPlay, or PlayReady. Those systems involve platform CDMs and licensing programs. A self-hosted key service cannot make this code implement them. The existing Axinom adapter is inactive in the runtime. Protected native clients, remote rendering, and media DRM interoperability are still engineering and validation work, not a provider configuration switch.
