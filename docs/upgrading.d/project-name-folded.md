## Project names are unique ignoring case and Unicode normalization on both backends

The unique index on live project names (`uniq_projects_name_active`) used SQL `LOWER(name)`.
SQLite's `LOWER` folds ASCII only and PostgreSQL's follows the database locale, so the two
backends accepted different sets of names. Projects now carry a `name_folded` column (NFC plus
case folding, computed in Go like `username_folded`); the same index name is rebuilt on it and
`GetProjectByName` looks up by it. This is schema epoch 10.

**What you will see on upgrade.** The column is added and backfilled for live projects, then the
old index is dropped and rebuilt. If two live projects fold to the same name, the server refuses
to start and changes nothing: no row is renamed, backfilled or deleted, and the old index stays.
The error ends with:

```
(project names must be unique ignoring case and Unicode normalization. The server cannot start to
rename them itself: with the server stopped, rename one project of each listed group directly,
e.g. UPDATE projects SET name = '<new name>' WHERE id = <id>, then start it again; nothing was
changed by this check)
```

and names the folded value and the project ids of each colliding group.

**What to do.** With the server stopped, rename one project of each listed group, for example:

```sql
UPDATE projects SET name = '<new name>' WHERE id = <id>;
```

then start the server again. Soft-deleted projects are not checked.

Project names created through the API, CLI or gRPC were already limited to letters, digits,
spaces, `-` and `_`, so existing installs are unlikely to be affected. A pair can exist only if
it was created before the ASCII-only name check applied to every writer.

**Mixed versions.** Do not run a pre-release build with a schema epoch from 3 to 9 together with
this build against the same database: such a build writes projects without `name_folded`. No
released version is affected (v0.96.3 is at epoch 2 or lower, and the epoch floor refuses it).
