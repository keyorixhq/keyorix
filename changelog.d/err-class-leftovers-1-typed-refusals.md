### Fixed
- **A storage fault no longer reads as "not found" for dynamic-secret configs, leases and machine tokens.** `ClassifyDynamicSecretConfig`, `SetDynamicSecretConfigEnabled`, `IssueLease`, `RenewLease` and the lease project/environment liveness check folded any read error into "config/lease not found"; a database outage now answers the retryable storage-unavailable class (HTTP 503, gRPC `Unavailable`) and a true not-found stays 404 / `NotFound`.
- **A driver message can no longer pick a gRPC status class.** The gRPC machine-identity, dynamic-secret and user mappers classify core's refusals by typed sentinel (`ErrMachineIdentityNotFound`, `ErrMachineTransitionInvalid`, `ErrMachineIdentityNotActive`, `ErrDynamicSecretNotFound`, `ErrValidation`) instead of words in the error text; a backend or driver error that says "permission denied" or "required" is a backend failure, not a caller refusal.
- **`POST /api/v1/audit/checkpoint` shows a checkpoint refusal reason by sentinel, not by text.** An unrelated storage error that happens to contain "refusing to checkpoint" is no longer echoed to the client (it stays in the log).

### Internal
- Deleted the `mapMachineError`, `mapDynamicError`, `isUntypedUserValidation` and `WriteAuditCheckpoint` rows from `errtext_classification_exceptions.tsv`.
