### Fixed

- Sharing a secret with a user who was deleted but still holds a project role grant (or a group deleted mid-request) answered an undeclared 500 "Failed to share secret". It now answers the same 403 an unknown recipient gets. Found by the nightly strict OpenAPI fuzz (#4641).
