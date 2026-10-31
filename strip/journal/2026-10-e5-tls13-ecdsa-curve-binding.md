# 2026-10 — E5: bind TLS 1.3 ECDSA schemes to the key's curve (#65)

## What

RFC 8446 §4.2.3 binds each `ecdsa_secp*` signature scheme to its curve and hash. Before this change the client
accepted a TLS 1.3 CertificateVerify from a P-384 leaf signed as `ecdsa_secp256r1_sha256` (0x0403, offered by the
client), as long as the SHA-256 ECDSA signature verified under the P-384 key. `BcTlsRawKeyCertificate.CreateVerifier(int)`
now compares the key's domain parameters with those of the scheme's named group
(`BcTlsECDomain.GetDomainParameters(SignatureScheme.GetNamedGroup(scheme))`, i.e. `NamedGroup.GetCurveName` +
`ECDomainParameters.LookupName`) and throws `TlsFatalAlert(illegal_parameter)` on a mismatch. TLS 1.2
(`CreateVerifier(short)`, `ecdsa` binds neither curve nor hash, RFC 8422 §5.4) is unchanged.

## Files

- `crypto/src/tls/crypto/impl/bc/BcTlsRawKeyCertificate.cs`: one hunk in the shared ECDSA block of
  `CreateVerifier(int)`, marked `// turbo-strip: E5`.
- `strip/smoke/rows/HostileSchemeCurveRows.cs` (new group `hostile-scheme-curve`, 8 rows): P-384 and P-521 signing
  as 0x0403, P-256 signing as 0x0503 and 0x0603 over TLS 1.3 → `illegal_parameter`; P-256/0x0403, P-384/0x0503,
  P-521/0x0603 over TLS 1.3 complete; P-384 with (sha256, ecdsa) over TLS 1.2 completes. The server is BASE
  (`SmokeHostileTlsServer` with a re-wrapped `SmokeServerKey`); BASE's `BcTlsECDsa13Signer` signs any ECDSA scheme
  with any EC key.
- `STRIP_PLAN_V2.md`: §3 E5 (binding enforced, rows named), §5 step 5 hostile list (new bullet), §7 reserve path
  (where the binding goes with the official DLL).

## Decisions

- Guard inside the shared case block instead of splitting the three secp cases off: one hunk, no moved case labels.
  The guard runs for every scheme with a named group: the three secp schemes and the brainpool tls13 schemes (RFC
  8734 binds those to their curves too; they are never offered, `VerifySupportedSignatureAlgorithm` rejects them
  first, and TurboKeyFactory rejects brainpool keys). `ecdsa_sha1` has no group (-1) and is not checked (never
  offered in TLS 1.3 either).
- Compare `ECDomainParameters` (curve, G, n) rather than OIDs: no `Asn1.X9` using, no reliance on the key being
  `ECNamedDomainParameters`, and an unknown or unresolvable group (null) fails closed with `illegal_parameter`.
- The check runs after `GetPubKeyEC()`, so a non-EC key under an ECDSA scheme still gets `certificate_unknown`.
- The alert is a `TlsFatalAlert`, which `TlsUtilities.Verify13CertificateVerify` rethrows unchanged (other
  exceptions become `decrypt_error`).

## How verified

- Rows first: `strip/strip.sh --work <dir>` on the unchanged library failed exactly the four mismatch rows
  ("expected TlsFatalAlert, nothing thrown"); the four accept rows passed.
- With the fix: `strip/strip.sh --work <dir>` (enforce + smoke) clean, all 8 rows pass, kept 680 files (unchanged),
  budget 748, deny 0.
- `./tools/ci/check.sh --full` at the pushed head.
