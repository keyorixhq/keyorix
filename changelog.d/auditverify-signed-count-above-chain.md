### Testing

- Added a test for the offline audit verifier's check that a validly signed checkpoint cannot certify more events than the chain holds. Planting "check off" in `verify.go` failed no test in the package before; it now fails `TestVerify_SignedCheckpointCountExceedingChainIsBroken`, with a control that the same checkpoint re-signed with the true count is VALID.
