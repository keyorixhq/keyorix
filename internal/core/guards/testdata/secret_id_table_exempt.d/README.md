# per-secret table exemptions: one file per table

`TestSecretGrantSweep_DeleteSecretAndProjectCascadeSweepTheSameTables` requires every table with a
`secret_id` column to be swept by both `DeleteSecret` and `deleteProjectCascade`, or to be exempt
here with the reason it grants nothing. It also fails on an exemption whose table is now swept by
both paths or no longer has a `secret_id` column. One file per table (GUARD-COLLISION-NOV-1), so a
PR edits only its own table's file instead of one shared list.

- One file per table, holding exactly one row: `table<TAB>reason`.
- The file name is the table name plus `.tsv` (`secret_version_comments.tsv`). The loader rejects
  any other name, so a table cannot sit in two files.
- The reason is one line a reviewer can check. If the table grants access, sweep it in both delete
  paths instead of exempting it.
- Files that do not end in `.tsv` (this README) are ignored.
