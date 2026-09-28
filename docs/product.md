# Product specification

## Vision and users

Creators publish digital assets with clear business rights. Customers can see what they may do before paying or opening an asset. Enterprise administrators assign seats and audit access. Security operators revoke compromised devices and keys without disabling unrelated content.

The first delivery focuses on a shared rights language. It does not present a marketplace or creator UI yet.

## Primary journeys

1. A creator selects a protection profile, reviews the permitted actions, duties, expiration, device limits, and compatibility report, then publishes an immutable policy version.
2. A customer receives an entitlement from a completed purchase or grant. The client proves possession of its registered device key, and the license service evaluates the entitlement and current policy before signing a short-lived license.
3. A customer opens an encrypted rendition with a trusted client. Revocation and renewal take effect at the next license check. Offline access lasts only for the signed bound.
4. An administrator investigates an anomalous issuance, revokes the device or entitlement, and follows an auditable incident workflow.

## Protection profiles

| Profile | Delivery | Typical use | Key trade-off |
| --- | --- | --- | --- |
| Public | Ordinary distribution | Open content | No technical access restriction |
| Controlled | Authenticated access | Low-risk paid content | Downloaded originals remain reusable |
| Protected | Encrypted packages and licensed clients | Books, documents, software resources | Client compromise can expose plaintext |
| High security | Hardware-backed keys and platform DRM where supported | Premium media | Device compatibility and offline access narrow |
| Maximum | Remote rendering or execution | Valuable source assets and models | Requires continuous connectivity and more infrastructure |

These are policy intentions. A target-specific compatibility report must succeed before publication. No profile guarantees prevention of screenshots, cameras, memory extraction, or redistribution after an authorized source export.

## Success criteria

- A cross-tenant request is always denied.
- Conflicting or unsupported policy rules fail publication with understandable reasons.
- A license requires a live entitlement, signed device challenge, and bounded expiry.
- Tampered encrypted chunks and manifests never return plaintext.
- The purchase and opening experience explains rights and recovery without manipulative friction.

## Feature map

Current: rights model, policy compilation, entitlement decision, device-bound license signing, chunk encryption.

Next product milestones: account and creator workflows; catalog ingestion; payments and durable entitlements; protected viewers and certified media DRM; offline native clients; enterprise seats and lending; royalty ledger; provenance, watermarking, claims, analytics, remote execution, SDKs, and operations.
