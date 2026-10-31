### Fixed

- **The audit checkpoint error says the signing key is derived from the KEK.** When encryption is off, the checkpoint endpoint (HTTP 412 and the gRPC `FailedPrecondition`) said the signing key was derived from the DEK. The key is derived from the KEK. Only the message text changed. Three code and test comments carried the same wording.
