### Added
- **Owner-scoped share list: a project-only owner can see and revoke their shares.**
  New `GET /api/v1/shares/owned` returns only the shares the caller created, on secrets in
  projects they are a member of now, within the caller's PAT restriction. The Sharing
  Management page falls back to it (labelled "Shares you created") when `GET /api/v1/shares`
  (global `secrets.read`) is refused; a global admin's page is unchanged.
