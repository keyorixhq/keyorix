# ADR-020: Project detail page — tabbed single page over separate top-level pages

## Status

Accepted, as-built. Backfill ADR — this decision predates the ADR series (it
sits chronologically between ADR-019's project cascade-delete and ADR-021's
RBAC Phase 2 roles catalog, both from the same May 2026 project-CRUD work).
Recorded now per the M2 "ADR backfill" backlog item, after a private-backlog
memory claim that this page was "still Proposed, blocked on a co-founder"
turned out to be stale — verified 2026-08-06 by reading the code directly and
driving the live page in a real browser: it is fully built, has been for
some time, and needed no new engineering work, only this missing document.

## Context

A project in Keyorix is the top-level unit almost everything else hangs off
of: its environments, its secrets, its human and machine members, its access-
review campaigns, and its own audit trail. Once `keyorix project describe`
(ADR-016) and `keyorix project env *` (ADR-017) existed on the CLI, the web
frontend needed an equivalent single place to manage a project's full
surface — not just view it.

The alternative to a single page was a set of separate top-level routes
(`/project-members`, `/project-secrets`, `/project-settings`, …), each
re-deriving which project it's scoped to from a query param or a picker.
That fragments a project's identity across the URL space and makes "which
project am I looking at right now" ambiguous outside a shared shell.

## Decision

One route, `/projects/:id/*`, rendered by `ProjectDetailPage.tsx`. It:

- Resolves the project once (`useProject(projectId)`), renders a breadcrumb
  (`Projects › {name}`) and a header (name + description), then hands off to
  a client-side tab bar backed by nested `react-router` `<Routes>` — so each
  tab is still its own bookmarkable/deep-linkable URL
  (`/projects/1/members`, `/projects/1/settings`, …), not client-only state.
- Records the visit in the ADR-018 MRU store (`useProjectMruStore`) on load,
  so both switcher-driven and direct-URL navigation feed the sidebar
  switcher's "Recent" ordering.
- Ships five tabs, each its own component under `web/src/pages/projects/`:
  - **Secrets** (`ProjectSecretsTab`, the largest at ~900 lines) — per-
    environment secret listing/search/filtering, plus the drift-check
    (`SecretsDriftPanel`, ADR-052-adjacent) and rotation-plan
    (`SecretsRotationPlanPanel`, ADR-053) panels embedded inline rather than
    as further sub-tabs.
  - **Members** (`ProjectMembersTab`) — human and machine-identity
    membership, project-scoped roles.
  - **Activity** (`ProjectActivityTab`) — the project's slice of the audit
    log, paginated.
  - **Access Review** (`ProjectAccessReviewTab` +
    `ProjectAccessReviewCampaigns`) — attest/revoke workflow and campaign
    tracking.
  - **Settings** (`ProjectSettingsTab`, the largest file at ~1,500 lines) —
    project metadata, per-environment lifecycle (restore, promote, delete),
    freeze-style controls, and the project delete flow (fronting the
    ADR-019 cascade-restrict endpoint with its confirmation modal).
- Defaults an index visit (`/projects/1`) to the Secrets tab via a redirect,
  rather than a separate "overview" tab — the secrets list *is* the
  overview for how this page is actually used.

## Consequences

- **Positive.** A project's full management surface lives at one URL prefix,
  keeps its identity in the URL (shareable/bookmarkable per-tab links), and
  shares one project-load + breadcrumb + MRU-recording path instead of
  five. New project-scoped concerns (drift, rotation planning, access-review
  campaigns) were added as more panels/tabs on this page rather than new
  top-level routes, and that pattern has held through several rounds of
  feature growth without needing to revisit the page's shape.
- **Negative / accepted tradeoff.** `ProjectSettingsTab.tsx` in particular
  has grown to ~1,500 lines by accumulating every project-lifecycle concern
  (metadata, environments, freeze, delete) in one component rather than
  splitting settings into its own sub-navigation. Not revisited here — it
  works and is tested, and splitting it is a refactor with no reported bug
  behind it, not a decision this ADR needs to make.
- Not built, and not implied by this decision: a dedicated "overview"/
  dashboard tab distinct from the Secrets tab. If a future need for
  project-level summary stats (beyond what the Secrets tab already shows)
  emerges, that's a new tab, not a change to this ADR's shape.
