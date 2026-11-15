### Fixed
- **Project Members tab listed no users to add.** It read `.data` of `GET /api/v1/users`, but the server sends the rows under `users`, so the add-member picker and the pending onboarding / access-request sections always saw an empty user list. `usersApi.list` and `adminApi.getUsers` now return the wire shape (`UserListResponse`).

### Testing
- **Reveal and Copy value (#2450) pinned at the HTTP boundary.** #2450 itself was already fixed on main; a new test keeps the real hooks and stubs only axios, with a versions response that has no value field and a value read that answers 200, 403, 404 or 503. A refused or malformed reveal shows the inline error with the server's reason and cannot unmount the page.
- **Response-field drift guard.** `responseFieldsDrift.test.ts` fails when the web requires a field of the secret list row, the secret version list or the user list that the `openapi.yaml` response schema does not define (calibrated red and green; it found the Members tab defect above).
- **Real-server Playwright spec for Reveal and Copy value** (`e2e/real/secret-reveal-copy.spec.ts`): success path of both controls, clipboard content, no page error.
