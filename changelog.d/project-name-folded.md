### Changed
- **Project-name uniqueness is the same on SQLite and PostgreSQL.** The partial unique index on live
  project names was on SQL `LOWER(name)`, which folds ASCII only on SQLite but follows the database
  locale on PostgreSQL, so the two backends accepted different sets of names (for example `ÄÖ` and
  `äö` as two projects on SQLite only). Projects now carry a `name_folded` column (NFC plus case
  folding, computed in Go like `username_folded`), the same index name `uniq_projects_name_active`
  is built on it, and `GetProjectByName` looks up by it. On upgrade the column is added and
  backfilled; if two live projects fold to the same name the upgrade stops with an error that names
  the folded value and the project ids, and changes no row: with the server stopped, rename one
  project of each group (the error gives the `UPDATE projects SET name = ...` statement) and restart. Soft-deleted projects are not checked. Project names created through the API, CLI or
  gRPC were already limited to letters, digits, spaces, `-` and `_`, so existing installs are
  unlikely to be affected.
