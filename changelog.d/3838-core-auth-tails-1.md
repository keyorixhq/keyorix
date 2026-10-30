### Security
- **An MFA-reset approver demoted or suspended mid-approval can no longer complete the reset (#3800).** The approver's admin role, active state and second factor were checked only before the approval transaction. They are now re-checked on the approver's row lock inside it, with the requester, approver and target locked in ascending user-ID order, so two admins approving each other's requests cannot deadlock.
- **A user whose MFA was reset must enrol a new second factor even without `security.require_mfa` (#3799).** The account-setup gate (HTTP and gRPC) now reads `users.mfa_enrolment_required`: such a session is confined to enrolment until a factor is enrolled, and TOTP activation clears the flag. Users who were never reset are unaffected.
- **The crypto inventory / CBOM is no longer sent when its read could not be audited (#3716).** `GET /api/v1/compliance/crypto-inventory` records `compliance.crypto_inventory_read` before answering, and answers 503 `audit_unavailable` (Retry-After) with no inventory when the row did not land.

### Fixed
- **Copying a restricted secret now says why it was refused (#3804).** `POST /api/v1/secrets/{id}/copy` answered a restricted-classification gate refusal (missing `secrets.read.restricted`, approval or recent step-up) with 404 "Secret not found". It is now 403 with the gate's reason; a caller who cannot read the secret at all still gets not-found.

### Testing
- **MFA-reset race tests now force the interleaving they claim (#3801).** A Postgres cross-replica test holds two create-requests for one target inside their transactions so only the target's row lock decides (with a no-lock calibration), the two-approver race holds both past the pre-transaction read and checks the loser is refused inside its transaction, and the second-factor-clearer guard also sees `SetUserMFAEnabled(false)` / `SetUserWebAuthnEnabled(false)` and cleared `MFAEnabled` / `WebAuthnEnabled` fields.
