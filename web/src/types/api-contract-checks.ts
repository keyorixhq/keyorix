// Compile-time contract checks against src/types/api-generated.ts (generated
// from server/http/handlers/openapi.yaml -- see package.json's
// generate:api-types / check:api-types-fresh).
//
// These exist to make a specific regression class impossible to ship
// silently: #2441 shipped because the web app's hand-written MFA request
// type made `password` optional (mfaApi.activate only ever took `code`),
// while the Go handler required it -- nothing in the type system connected
// the two. The generated ActivateMFA request type below requires `password`
// because openapi.yaml's requestBody schema now says so (see the QA-2
// session's spec additions). This file is the proof that a caller omitting
// it is a TYPE ERROR, not just a runtime 400 discovered after shipping --
// delete the `// @ts-expect-error` line to see it fail on its own.
//
// Not wired into web/src/services/mfa.ts yet: that file is being edited by
// an in-flight PR fixing #2441 itself (adds the missing password param) --
// wiring the service to this generated type is a direct follow-up once that
// PR lands, not redone here to avoid a two-way edit conflict on the same
// lines.
import type { operations } from './api-generated';

type ActivateMFARequest = operations['activateMFA']['requestBody']['content']['application/json'];

// @ts-expect-error - password is required by ActivateMFA's openapi.yaml requestBody schema; omitting it must fail type-checking, the same way #2441's web code silently sent no password at runtime.
export const activateMfaRequestRequiresPassword: ActivateMFARequest = {
    code: '123456',
};

// The correct shape, for contrast -- both fields present compiles cleanly.
export const activateMfaRequestValidExample: ActivateMFARequest = {
    code: '123456',
    password: 'correct-horse-battery-staple',
};

type LoginResponseData = operations['authLogin']['responses'][200]['content']['application/json']['data'];

// #2442 shipped because the web app's login flow never checked for
// `mfa_required` in the response at all. This doesn't force that check (a
// type can't force a caller to branch on a field), but it does force the
// field itself to exist and be typed -- a renamed/removed mfa_required
// would now be a compile error anywhere it's actually read.
export const loginMfaChallengeExample: LoginResponseData = {
    mfa_required: true,
    mfa_challenge: 'challenge-token',
    totp_available: true,
    webauthn_available: false,
};
