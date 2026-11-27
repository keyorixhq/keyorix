### Documentation

- `server/authzdiff/EXTENSION-PLAN.md`: added a dated V5-PLAN-2 section re-ranking the 103 operations still uncovered after the ten-op binding (REST 120/212), reconciling the previous session's "cannot bind" reasons against what was actually bound (several — notably `webauthn.deleteCredential` — were stale), and regrouping the remaining work into deny-first, route-gate batches R1–R8. Docs only; no harness or product code changed.
