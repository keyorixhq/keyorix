### Internal
- **Removed the caller-free full-row `UpdateDynamicSecretConfig` storage primitive.** Dynamic-secret config writes already go through column-scoped writers; no behaviour change. Also fixed a time-of-day flake in the schema-epoch diagnostic test (expected date now formatted in UTC) and clarified stale `UpdateUser` comments.
