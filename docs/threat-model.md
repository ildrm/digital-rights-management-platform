# Threat model: foundation

## Assets and trust boundaries

Protected assets include source files, per-rendition content keys, policy versions, entitlements, license signing keys, device public keys, payment records, and audit evidence. Creators, customers, administrators, native clients, browsers, the public API, workers, object storage, PostgreSQL, OpenBao, and optional DRM vendors occupy separate trust zones. Client devices and networks are hostile. Production signing and wrapping keys must remain in a protected key service such as OpenBao Transit.

## Threats and controls

| Threat | Current control | Remaining work |
| --- | --- | --- |
| Cross-tenant entitlement use | Tenant IDs checked across principal, device, entitlement, policy; PostgreSQL RLS; OIDC tenant claim mapped to active user | Identity-provider tenant-claim review and full API authorization campaign |
| Forged entitlement or duty state | Decision checks status, version, time, action, and duties; database issuance loads the grant and policy from PostgreSQL | Authenticated API and financial evidence |
| Device impersonation/replay | Ed25519 enrollment proof, one-time challenges, fingerprint uniqueness, owner-only revocation | Hardware-backed enrollment and attestation |
| Token forgery or tenant injection | OIDC signature, issuer, audience, age, scope, and tenant validation; request body rejects tenant/user fields | Live IdP configuration and negative integration tests |
| License-signing abuse | PostgreSQL per-user rate windows and three pending challenges per device | Gateway IP/anonymous limits, bot and anomaly controls, provider quota monitoring |
| License alteration | Ed25519 signature over a domain-separated digest of claims and device binding; verifier checks pinned OpenBao key version; live Transit interoperability test | Signing-key rotation, revocation distribution, client verifier |
| Clock rollback | Signed expiry, server time on issuance, explicit online/offline state, and `offlineUntil` enforcement in the library | Trusted offline time ledger and rollback detection in native clients; caller-supplied connectivity is not a security boundary in an untrusted client |
| Content tampering or cross-asset substitution | Signed manifest through asynchronous signer, AEAD associated data, ciphertext hash, licensed chunk opening; live OpenBao/SeaweedFS round-trip | Parser fuzzing and streaming |
| Key theft | OpenBao Transit wrapping with tenant-derived key context and authenticated asset metadata; no embedded production root | TLS, scoped token, durable seal/unseal, audit, rotation and incident drills |
| DRM token replay or sharing | Axinom message scoped to one key and 30 seconds after verifying a signed online license | Live provider replay controls, CDM/device binding and robustness verification |
| Screen capture and memory extraction | No claim of impossibility | Certified DRM/TEE where available, watermarking, remote execution |
| Malicious uploads | Separate `drm:publish` scope, per-user quota charged before body parsing, 8 MiB decoded limit, strict policy compilation, encrypted object write | MIME inspection, sandboxed processing, malware scanning, edge limits and abuse controls |
| Concurrent seat abuse | Database issuance locks the entitlement and counts other active devices | Dedicated session lease service and wider concurrency policies |
| Privileged operator abuse | No operator API currently exposed | Separation of duties, step-up authentication, audit, approval workflow |

## Security review and residual risk

The tests exercise negative paths for tenant mismatch, expired grants, prohibited action, missing duty, altered license, replayed proof, altered ciphertext, altered manifest, wrong package identity, key scope, and a simultaneous device-seat race. The active OpenBao and SeaweedFS adapters passed disposable live-service tests and a PostgreSQL-backed publish-to-license round-trip. AWS and Axinom adapters remain inactive and have only fake-transport tests. This is not a penetration test, cryptographic certification, or claim of production security. A legitimate client can recover plaintext once authorized unless execution/rendering stays remote. Offline revocation is bounded by the lease duration.

The core licensing interface accepts usage counts and duty fulfillment from its caller. That caller must be a trusted server-side application reading durable authoritative state. It must never copy those values from customer requests. The PostgreSQL path reads device counts from the database and rejects constraints it cannot verify. The issuer injects its own trusted clock and ignores the request's time value. The API limits body size and fields; its OIDC verifier has not been tested with a live identity provider. The gateway must provide TLS and network isolation because the app currently serves internal HTTP.

`activeDeviceCount` means other active devices that would count against the limit, and `activeSessionCount` means sessions excluding the requested one. The PostgreSQL path serializes device-seat grants with an entitlement row lock. OpenBao Transit supplies the active key-reference verifier and signer, but the disposable test did not exercise production TLS, scoped tokens, backup, or failover. Risk checks and a session lease service remain necessary before public issuance. The inactive Axinom adapter accepts a verified license through a trusted backend; its bearer token does not itself bind a CDM to the registered device.
