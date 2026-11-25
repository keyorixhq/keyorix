# ADR-123: The web UI teaches itself with one-time page hints, not guided tours

**Status:** Proposed (2026-11-25). Direction given by Andrei on 2026-11-25; it becomes Accepted when
he approves this text. It is meant as a principle for the whole web application, so every later UI
change is checked against it. No code follows before approval.
**Date:** 2026-11-25
**Origin:** Follow-up interview with the author of the 2026-11-21 devops.org.ru review (an
infrastructure lead who runs Vault). Notes: Keyorix planning notes,
`claude/2026-11-25-friend-cto-interview-requests-and-next-steps.md`.

## The principle

Keyorix explains its interface once, in place, on the page where the question arises. It does not
walk the user through the product.

1. **One short hint per primary page**, saying what each control on that page does and, where the
   page rests on a concept that is easy to misread, what that concept is.
2. **Shown once per user.** After it is dismissed it does not return by itself.
3. **Always reachable again** through a visible help control on the page.
4. **Never in the way.** The hint does not dim the page, trap focus, block input or cover the
   controls it describes.
5. **No guided tours.** No step-by-step overlays, no product-tour libraries, no forced first-run
   walkthrough, no checklists that must be completed.

The audience is DevOps and security engineers. They read the page and work it out; they need the
unfamiliar part named, not to be led by the hand.

## Context

The evaluator tested Keyorix on an empty stand. On environments he answered: from the first screen
he did not understand that dozens of projects can be gathered into one environment; seeing
"Production, 12 projects", clicking it and seeing the list would have put everything in place.

Andrei had considered an interactive tour on a user's first visit, like the one Doppler has. The
evaluator preferred a one-time hint on each page saying what each control does: technical people
work it out themselves, and a tour is for audiences Keyorix does not target.

Two separate things are in his answer, and this ADR deals only with the first:

- **Teaching** (this ADR): a one-time hint per page.
- **Model** (not this ADR): his picture of an environment is a cross-project group, while in
  Keyorix environments belong to a project (the project creation page says so, and the project
  list shows an environment count per project). A hint does not replace a clear model, and the
  cross-project environment overview he asked for is a separate product decision.

## Rules

1. **Scope.** A hint describes controls and concepts on its own page. It is not a feature
   announcement, a marketing message, an upsell, or a place for warnings that belong in the
   flow itself.
2. **Content.** Plain text, a few short lines, kept with the other interface strings so it is
   translated with the rest. It never shows secret values, real user data or anything the server
   returned.
3. **Not modal.** A modal dialog that hides the page from assistive technology and from role-based
   test queries is ruled out (the MFA enrolment work found that an open Radix dialog hides the
   background). The hint is an inline region or a non-modal popover, reachable by keyboard, with
   an accessible name.
4. **State.** "Seen" is remembered per user and per hint id on the server, as a per-user UI
   setting stored in SQL ([ADR-124](adr-124-server-side-user-preferences.md)), with keys of the form
   `hint.<id>`. It is not kept in `localStorage`, so a hint does not come back in another browser
   or after a cleared profile. It is a UI preference, never a credential.
5. **Re-show.** A hint is shown again only when its text changes in a way that matters, by raising
   the hint's version. Wording fixes do not.
6. **Mandatory security flows are not hints.** A flow the deployment requires, such as first-login
   MFA enrolment, is a functional step and may open by itself. It does not teach; it completes a
   required action.
7. **Air-gapped by default.** Hints are bundled with the application. No external scripts,
   fonts, CDNs, or analytics services; nothing is sent anywhere when a hint is shown or dismissed.
8. **Tests.** Every page that has a hint has tests for: shown on first visit, not shown after
   dismissal, reopened by the help control, and not blocking the controls of the page. End-to-end
   specs set the "seen" state in setup, so a hint never changes what they click.

## Alternatives considered

- **Interactive tour on first login (Doppler style).** Rejected: wrong audience, interrupts
  people who came to do one task, breaks when the interface changes, needs its own maintenance and
  test machinery, and tends to be dismissed without being read.
- **Documentation only.** Rejected as the only channel: it is not where the question arises. Docs
  stay, and hints may link to them.
- **Permanent tooltips and inline captions everywhere.** Rejected: clutter for people who already
  know the page. A one-time hint with a re-open control gives the same text without the noise.
- **Video or animated onboarding.** Rejected: heavy, hard to keep current, not suitable for
  air-gapped deployments.

## Open decisions

- Which pages get a hint first, and the text for each. Suggested order: projects list (environments
  belong to a project), secrets, machine identities, dynamic secrets, audit, administration.
- The shape of the help control and where it sits in the page header.

## Consequences

New pages ship with a hint or state why they do not need one. Reviewers check new UI against this
principle. No new dependency is added. The cost is one small shared component, hint texts for the
primary pages, and the tests above; none of that exists in `web/src` today. The "seen" state depends on the
server-side settings store in ADR-124, so the hint work follows that one.
