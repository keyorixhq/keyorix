### Testing

- Fuzz oracles: the TPM attestation oracle accepts ESP256 (-9) and tolerates ES256K (-47) with a P-256 AIK until #4545, pinned by a library test (KFZ-2026-165/166); the configcompat and configspace key-echo masks handle spaced key names and stop at "; "-joined construct errors; configspace I4 exempts only a canary echoed from a non-secret field of a loaded config and fails closed for load errors, env-sourced secrets and sequence secrets (KFZ-2026-167).
