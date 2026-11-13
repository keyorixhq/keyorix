### Fixed

- Web: the project Settings "Require MFA" Save is offered only to a session that holds both `roles.assign` and `secrets.write` (the server needs both: the route checks `secrets.write`, the handler `roles.assign`), so a custom role with only `roles.assign` no longer sees a Save that ends in a refusal.
- Web: the Dynamic Secrets page offers New config, the classification picker and lease management to a session with `secrets.write` (what the server routes require) instead of to install administrators only.

### Testing

- Web: unit cases for the project Settings sections that were hidden but untested (Extend all, Apply renames and the disabled rename inputs, Restore secret, Reassign owner), asserted visible for a permitted session and absent for a viewer.
- Web: test-local `useCan` literals now spread shared `ALL_CAN` / `NO_CAN` defaults (`web/src/test/can.ts`), so they track the `Can` shape.
- Web: a real-backend Playwright spec (`web/e2e/real/permission-gating-surfaces.spec.ts`) for the project Settings tab, the project Access Review tab and the Rotation Policies page: no write control for a project viewer, all of them for the admin.
