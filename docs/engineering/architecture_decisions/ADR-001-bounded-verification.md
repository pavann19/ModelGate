# ADR-001: Bounded explicit-key signature verification

Date: 2026-11-04. Status: accepted for local candidate; interoperability validation required before release.

## Observed problem

The admission verifier currently starts `cosign verify-blob` for each candidate signature, writes temporary key/payload files and ships a large general-purpose CLI. The retained 2026-11-03 binary scan reports 13 upstream findings. Removing that binary removes its runtime dependency surface; it does not prove those findings exploitable or prove the remaining application secure.

## Alternatives

Keep the CLI and wait for upstream fixes; import the Sigstore verification dependency graph; or use Go standard-library verification for the specific legacy payload format already fetched and identity-checked by ModelGate. Choose the last option because the supported fixtures use an explicit PKIX ECDSA P-256 key and ASN.1 signature over SHA-256. No new cryptographic primitive or algorithm is introduced.

## Versioned compatibility and trust contract

This is a **breaking algorithm-contract narrowing** relative to the general Cosign CLI, which may accept RSA, Ed25519 or other key types. The new bounded-v1 contract accepts only one PEM `PUBLIC KEY` block containing PKIX ECDSA P-256, with no headers, extra blocks or non-whitespace trailing/prefix data. Existing deployments using other key types must retain the earlier release until deliberately migrated by their operator. Do not silently rotate trust roots or claim general Cosign compatibility.

Verify standard base64 DER ASN.1 ECDSA signatures over SHA-256 of the exact fetched payload bytes. Maximum key input: 16 KiB; payload: 64 KiB; encoded signature: 16 KiB; decoded P-256 signature: 72 bytes. Reject canceled requests before and after bounded cryptographic work. No key discovery, certificate trust, keyless identity/issuer, Rekor, TUF, timestamp, revocation, attestation, provenance or expiry assurance is added. The operator-owned per-request public key remains the sole signing trust anchor. Registry/TLS destination policy, exact repository/digest/type checks and 16-layer bound remain unchanged; no parser fallback or network fallback is permitted.

The upstream [Cosign signature specification](https://github.com/sigstore/cosign/blob/main/specs/SIGNATURE_SPEC.md) identifies ECDSA P-256/SHA-256 as its baseline algorithm. Go's [VerifyASN1](https://pkg.go.dev/crypto/ecdsa#VerifyASN1) performs standard signature verification. These are interoperability references, not an assertion that all Cosign modes are supported.

## Validation plan recorded before implementation

Run existing webhook tests before and after the change. Add valid/wrong-key/tampered-payload/malformed-base64/invalid-DER/trailing-data/oversize/unsupported-key/cancellation controls. Independently ask pinned Cosign v3.1.4 to verify Go-generated signatures and compare negative outcomes; keep Cosign as a test oracle only. Keep the existing TLS-registry integration API compatible and rerun its positive and negative controls where isolation prerequisites hold. Missing oracle or unsafe registry isolation must be reported as skipped/blocked, never passed. This ADR does not authorize cluster or shared runtime access.

## Trade-offs

Smaller shipped dependency surface, no temporary verification files or per-signature process, and explicit bounded algorithms; narrower interoperability and ongoing responsibility to test encoding compatibility. No performance improvement is claimed without matched measurements. Preserve the old type name `CosignVerifier` for source compatibility, while documenting bounded-v1 semantics.

## Validation evidence

The independent Cosign v3.1.4 interoperability test and real TLS-registry/API-server tests passed locally. Reproduction, algorithm limits and remaining deployment gates are documented in [the security demonstration](../../security/DEMONSTRATION.md). No full Cosign compatibility or production certification is claimed.
