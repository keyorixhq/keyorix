# ADR-125: Certificate issuing: integrate external CAs first, own CA later

**Status:** Proposed (2026-11-25). Preliminary: recorded so the question and its constraints are not
lost. It becomes Accepted only when Andrei approves this text. No code follows from this ADR.
**Date:** 2026-11-25
**Origin:** Follow-up interview with an infrastructure lead evaluating Keyorix (2026-11-25), the
same evaluator whose input produced [ADR-122](adr-122-read-only-site-replica.md). The facts this
ADR relies on are restated below so it can be read on its own.

## Non-negotiable invariants this ADR must not weaken

- **Audit-before-disclosure** ([ADR-112](adr-112-secure-by-default-baseline.md), baseline item at
  line 108; [ADR-115](adr-115-local-audit-journal.md)): a secret value is never returned before its
  audit record is committed, and a failed audit write fails the request.
- **Authorization is not widened.** Issuing a certificate is authorized by the same core
  authorization path as every other value-producing operation; no issuer gets its own side door.
- **Fail closed.** An issuer that cannot be reached, or a policy that cannot be evaluated, refuses.
  There is no "issue anyway" fallback.
- **Private keys are secrets.** Any private key Keyorix holds is encrypted at rest and never logged,
  exactly like the admin DSN and the issued credential of a dynamic secret today.

## Context

### The signal, stated honestly

One infrastructure lead who runs HashiCorp Vault said that what he values most in Vault is its
certificate authority (the PKI engine): it gives him mTLS and "a lot of other useful things". Next
on his list came the database engines, an identity directory (FreeIPA/AD) and the Kubernetes client
(Vault Agent). This is one voice. He is an evaluator, not a prospect, and he stated no requirement.
This ADR records the question and a preliminary direction; it does not commit to a feature.

### What Keyorix has today (verified on main, 2026-11-25)

- **Stores and inspects certificates.** `InspectCertificate` parses the leaf X.509 certificate of a
  secret and returns public metadata only (`internal/core/certificate.go:51`, parser at
  `internal/core/certificate.go:199`; a `PRIVATE KEY` block is never parsed,
  `internal/core/certificate.go:189`). Audited as `secret.certificate_inspected`
  (`internal/core/certificate.go:23`). Certificate-typed secrets have `Type == "certificate"`
  (`internal/core/certificate.go:131`). Design: [ADR-054](adr-054-certificate-inspection.md).
- **Monitors expiry.** `ScanCertificateExpiry` reads each certificate's real `notAfter` and sends
  one digest per project (`internal/core/certificate_expiry.go:36`), run by an opt-in scheduler
  (`server/scheduler_certificate_expiry.go:16`). Design: [ADR-055](adr-055-certificate-expiry-monitoring.md).
- **Reports hygiene.** `SecretNode.CertNotAfter` caches the parsed expiry
  (`internal/storage/models/models.go:1067`) and feeds the compliance control; rotation refreshes it
  (`refreshCertNotAfterCache`, `internal/core/certificate.go:140`). Design: [ADR-056](adr-056-certificate-hygiene-posture.md).
- **Mints short-lived credentials.** The dynamic-secrets engine ([ADR-035](adr-035-dynamic-secrets.md),
  Kubernetes in [ADR-058](adr-058-kubernetes-dynamic-secrets.md)) has one backend interface,
  `ports.DynamicBackendEngine` (`Issue`, `Revoke`, `Renew`, `SupportsNativeExpiry`, ...;
  `internal/core/ports/ports.go:160`), aliased as `dynamic.CredentialEngine`
  (`internal/dynamic/engine.go:39`) and built only by `dynamic.New`, which wraps every engine in a
  panic-containing `Contain` (`internal/dynamic/engine.go:82`). `IssueLease`
  (`internal/core/dynamic_secrets.go:601`) decrypts the admin DSN (stored encrypted,
  `internal/core/dynamic_secrets.go:323`), mints, encrypts the credential under an AAD bound to the
  lease, persists the lease and revokes the target account if a later step fails
  (`internal/core/dynamic_secrets.go:675-722`). `RevokeLease` and `RenewLease` are at
  `internal/core/dynamic_secrets.go:781` and `:1113`.
- **Delivers to Kubernetes.** The sync agent writes `Opaque` Secrets
  (`internal/k8ssync/rest_sink.go:193`); the operator ([ADR-060](adr-060-kubernetes-operator.md))
  lets a `KeyorixSecret` choose the target Secret type, default `Opaque`
  (`operator/api/v1alpha1/keyorixsecret_types.go:70-73`); ESO is the third path
  ([k8s-eso.md](k8s-eso.md)).
- **TLS for its own listeners.** HTTP and gRPC load a static certificate and key with hot reload
  (`server/tls_config.go:24`, `server/grpc/server.go:323`, `internal/tlsreload/tlsreload.go:63`),
  or, for HTTP only, obtain one by ACME through `golang.org/x/crypto/acme/autocert`
  (`server/tls_config.go:83-101`). The air-gapped build refuses `auto_cert`
  (`internal/config/airgap_profile.go:13-26`; [AIRGAP_RUNBOOK.md](AIRGAP_RUNBOOK.md) line 31 says to
  use certificate files from an internal CA). `keyorix admin init` can generate one self-signed
  server certificate (`server/admin/init_secure.go:136-168`). The listeners do not request or verify
  client certificates: there is no `ClientAuth` setting in `server/` or `internal/`.

### What Keyorix does not have

No certificate issuing for anyone else: no CSR handling, no signing, no CA, no issuer integration.
A search for `x509.CreateCertificate`, `CreateCertificateRequest`, `acme` and `autocert` outside
tests finds only the three items above (autocert for its own HTTP listener, the self-signed init
certificate, and a SAML test helper in `internal/saml/samltest/samltest.go:58`). Certificates in
Keyorix today are put there by an operator.

### Why it matters

mTLS between services needs a certificate per service, renewed often; sites and gateways in
[ADR-122](adr-122-read-only-site-replica.md) each need their own; a short-lived certificate is least
privilege for machine identity in the same way a short-lived database role is, which is the
NIS2 Art. 21 / ENS `op.acc.*` argument [ADR-035](adr-035-dynamic-secrets.md) already makes.

## Options

- **(A) Integrate external issuers.** Keyorix requests, stores, delivers and renews certificates
  from a CA the customer already runs: ACME (public or internal), an on-premise CA such as step-ca,
  cert-manager, Vault PKI or OpenBao PKI, an enterprise CA. An issuer interface sits next to the
  dynamic-secrets backends.
- **(B) A built-in CA.** Root and intermediates, issuance, revocation by CRL/OCSP, a key ceremony,
  root storage in an HSM or TPM.
- **(C) Do nothing.** Operators keep issuing elsewhere and storing the result; ADR-054/055/056 keep
  watching it.
- **(D) A small per-site CA, later,** tied to ADR-122 (a site issues local certificates while offline).

## Decision (Proposed)

**A first.** It reuses the lease, encryption, audit and delivery machinery that exists, adds no new
root of trust to protect, and fits customers who already run a CA, which is where an air-gapped or
regulated estate usually is.

**B is deferred.** Reopening trigger: two or more prospects who need their own CA with revocation
and cannot use an existing one. Before any code, B needs its own threat model and its own
key-ceremony ADR (root generation, custody, HSM/TPM, rotation, compromise recovery). Today's TPM
provider seals the KEK without a PCR policy (`internal/crypto/tpm_provider.go:11-19`;
[ADR-117](adr-117-tpm-sealed-kek-pcr-policy-recovery.md) is Proposed), so it is not yet a basis for
root-key custody claims.

**C is rejected** as the long-term answer: it leaves Keyorix monitoring certificates it can never
renew. **D is not decided here;** it waits for ADR-122.

## Design points for A (each with its rule)

1. **Key generation side.** Prefer the consumer generating the key pair and sending a CSR: the
   private key then never reaches Keyorix. If Keyorix generates the key (for consumers that cannot),
   the key is a secret: encrypted at rest under the existing encryption service with an AAD bound
   to the lease, as `IssueLease` does for credentials, returned once, never logged.
2. **Audit before hand-over.** The issuance audit record is committed before the certificate or key
   is returned, and a failed write fails the request (ADR-112 doctrine). Note: the dynamic-lease path
   does not do this today; `dynamic_lease.issued` is written after the lease is persisted and its
   result is not checked (`internal/core/dynamic_secrets.go:725-727`), and ADR-112 classes that event
   as a create (`docs/adr-112-secure-by-default-baseline.md:405`). A certificate issuer must use the
   fail-closed pattern of `LogSecretReadWithProject` (`internal/core/audit.go:529-539`), not copy
   `IssueLease` as is.
3. **Issuer credentials are ordinary secrets** with least privilege: an ACME account key, a
   step-ca provisioner, a Vault/OpenBao token or an enterprise-CA client certificate is stored like
   the admin DSN (encrypted, never returned by the API) and scoped to the narrowest role the issuer
   offers.
4. **Policy in Keyorix, before the call.** Allowed names and SANs, maximum TTL, key types and who may
   request are checked by Keyorix before it contacts the issuer, with an install-wide ceiling on top
   of per-config limits, as `dynamic_secrets.max_lease_ttl` does for leases
   ([ADR-035](adr-035-dynamic-secrets.md), 2026-07-06 addendum). An issuer's own policy is a second
   line, not the first.
5. **Short TTL and renewal.** Short lifetimes by default; renewal re-issues before expiry. The ADR-035
   lease shape (TTL, max TTL, renew, revoke-all) is the model.
6. **Revocation is stated per issuer.** Some issuers revoke by CRL/OCSP, some barely, and a relying
   party that does not check revocation ignores it anyway. Each issuer documents what `Revoke` does,
   as `RevokeInvalidatesCredential` already does per dynamic backend
   (`internal/core/ports/ports.go:167-172`). Short TTL is the primary control.
7. **Air-gapped installations** cannot use public ACME, as Keyorix's own listener already shows
   (`internal/config/airgap_profile.go:13`). They need an on-premise issuer (internal ACME, step-ca,
   an enterprise CA). The air-gapped build must refuse a public ACME directory, not time out on it.
8. **Issued certificates keep the existing checks.** An issued certificate is stored as a
   certificate-typed secret, so ADR-054 inspection, ADR-055 expiry monitoring and the ADR-056
   control apply without new code paths.
9. **Delivery** reuses the existing three Kubernetes paths. The operator passes `spec.target.type`
   through to the Secret (`operator/internal/controller/keyorixsecret_controller.go:665-668`), so a
   `kubernetes.io/tls` Secret is possible, though not tested end to end; the sync agent writes
   `Opaque` only. Non-Kubernetes hosts need an
   agent, which is out of scope (below).
10. **Sites (ADR-122)** get certificates through the same path. A lost link must not make renewal
    fail open: a site never extends a certificate itself, the certificate's own `notAfter` is the
    bound, and lifetimes for sites are chosen with the offline window in mind.

## What this ADR does not decide

The agent for non-Kubernetes hosts (template rendering, caching, auto-renewal: a separate ADR); SSH
certificates; transit encryption; directory (FreeIPA/AD) credentials; database engines beyond
ADR-035; client-certificate authentication to Keyorix's own listeners.

## Alternatives considered

- **B now.** Rejected for now: a CA is a new root of trust with revocation, ceremony and custody
  obligations, built on one evaluator's remark, while A covers the customers who already run a CA.
- **Wrap cert-manager only.** Too narrow: it covers Kubernetes and leaves hosts, sites and air-gapped
  installs without a path. cert-manager stays one issuer among several.
- **Treat issuance as a new `dynamic.CredentialEngine` backend.** Tempting, but the interface takes
  an admin DSN and a creation template and returns username, password and string fields
  (`internal/core/ports/ports.go:151-161`); a CSR, a chain and per-issuer revocation do not fit it
  cleanly. Whether to extend it or add a sibling interface is open decision 1.

## Consequences

Nothing changes in the product today. If accepted, A adds an issuer interface, issuer configs with
encrypted credentials, an issuance policy, issue/renew/revoke endpoints with fail-closed audit, and
documentation of revocation per issuer. Each issuer is its own small PR with its own tests. B and D
remain closed until their triggers are met.

## Security considerations

- New stored secrets: issuer credentials and, when Keyorix generates keys, private keys. Both follow
  the invariants above.
- A compromised issuer credential lets an attacker obtain certificates within that credential's
  scope at the issuer. Least privilege at the issuer and Keyorix-side policy (point 4) bound it.
- SAN and name validation is a classic injection and confusion surface; policy checks must be
  exact-match or explicitly-anchored patterns, with fuzzing like other parsers in this repository.
- Revocation that does not work must not be advertised (point 6).
- Issuer outages fail closed for issuance; already issued certificates keep working until expiry and
  ADR-055 warns before then.

## Open decisions

1. Issuer interface shape: extend `ports.DynamicBackendEngine` or add a sibling port.
2. Key generation side: CSR only, Keyorix-generated only, or both with a per-config switch.
3. Which issuer first (ACME, step-ca, Vault/OpenBao PKI, cert-manager, an enterprise CA).
4. Revocation story per issuer, and what Keyorix shows the operator.
5. Sites (ADR-122): lifetimes, renewal while offline, and whether D is ever needed.
6. HSM/TPM: whether Keyorix-generated keys or issuer credentials need hardware storage.
7. Licence and packaging: which edition carries issuers.

## Questions for the evaluator

- What exactly do you issue through Vault PKI today (server, client, both; internal names or public),
  and with which lifetimes?
- Do you need your own root and revocation, or certificates from an existing CA delivered and renewed?
- By "Vault Agent", do you mean template rendering, caching, auto-renewal, and on Kubernetes, plain
  hosts or both?

## Verification

This ADR enforces nothing; it states no property a test can check today. Statements about Vault PKI,
OpenBao, step-ca, cert-manager, ACME and CRL/OCSP are general knowledge and must be verified against
current documentation before this ADR is accepted.
