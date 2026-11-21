### Added
- **The degraded break-glass count is visible to the people who read the posture.** `emergency_access.degraded_activations` (activations committed while the audit log refused their rows, whose audit rows are still owed) is now declared in the gRPC `EmergencyAccessPosture` message and described in the OpenAPI posture response, and the web compliance page shows it as a "Break-glass degraded (audit rows owed)" tile with a "Review owed" hint when it is above zero. An older server that does not send the field leaves the page unchanged. Guarded by `TestEmergencyAccessPosture_RESTFieldsAreDeclaredInProto`.

### Testing
- **The emergency-access control status for degraded activations is pinned.** A degraded activation keeps the control a Gap while it is unreviewed, Unknown once reviewed with audit rows still owed, and Pass once reviewed and settled (`TestEvaluateControls_EmergencyAccessDegradedActivationTable`). No behaviour change.
