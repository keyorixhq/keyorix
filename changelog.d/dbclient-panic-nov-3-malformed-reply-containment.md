### Security

- A malformed server reply from a database target of a dynamic-secret backend or an auto-rotation backend is now covered by regression tests for every backend and for TLS connections, where the plaintext wire guard does not apply: the failure comes back as an error that names the backend and the operation and none of the reply, never as a crash. The hardening guide now says that operator-supplied database endpoints must not rely on the wire guard when TLS is on (#4133, #4777).
