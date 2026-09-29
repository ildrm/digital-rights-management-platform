# Standards baseline checked 2026-09-29

- [W3C ODRL Information Model 2.2](https://www.w3.org/TR/odrl-model/) is the current Recommendation identified for rights semantics. This repository is inspired by ODRL and does not claim full ODRL JSON-LD import/export conformance.
- [NIST SP 800-63-4](https://www.nist.gov/publications/nist-sp-800-63-4-digital-identity-guidelines) is the current final digital identity guidance. Identity implementation is pending.
- [W3C WCAG 2.2](https://www.w3.org/TR/WCAG22/) is the accessibility target. No customer UI exists yet, so conformance is untested.
- [Next.js security releases](https://nextjs.org/blog) identify 16.3.6 as the active LTS security release available by this date. No web app has been selected or installed yet.
- [TypeScript npm package](https://www.npmjs.com/package/typescript) lists stable 7.0.2, used for the typecheck.
- [C2PA specifications 2.4](https://spec.c2pa.org/specifications/specifications/2.4/) are available. Provenance integration is pending.

Additional implementation reviews must verify OWASP ASVS/API/MASVS, NIST SSDF and key management, OAuth/OIDC/WebAuthn/SCIM/SAML, EME/Common Encryption/DASH/HLS, EPUB/Readium LCP, and provider-specific DRM contracts at the time those modules are built. No conformance or certification is asserted from this baseline alone.
