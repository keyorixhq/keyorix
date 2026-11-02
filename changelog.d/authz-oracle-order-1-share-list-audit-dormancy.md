### Security
- **The share list writes one `share_access_elevated` audit row per call, not one per secret (#3456).** `GET /api/v1/shares` and `/shares/owned` name each secret the caller may read; a name readable only through a share used to write its own `share_access_elevated` row on every list call. The list now writes a single row with action `shares.list`, the count and up to 50 secret/share ID pairs (`truncated` when there are more). A caller whose role already allows every read writes none. An elevated read or write of one secret is still audited per action, as before. See `docs/SECRET_SHARING_API.md`.

### Changed
- **Dormant role grants use the recertification cadence as their threshold (#3459).** The compliance posture, the `dormant-access` control and the digest used to call a grant dormant after a fixed 90 days without use. They now use `recertification.cadence_days` (default 90, at most 366), the same window the access review's "last used" already uses. With the default cadence nothing changes. A shorter cadence flags more grants, a longer one fewer. See `docs/recertification-activity-window.md` and `docs/UPGRADING.md` §6w.

### Testing
- **`audit search --actor` is pinned over REST for users and machine identities (#3736).** A real machine-token read and a real session read are each found by `GET /api/v1/audit/search?actor=` under the name the ACTOR column shows. The storage fix landed in #3836.
