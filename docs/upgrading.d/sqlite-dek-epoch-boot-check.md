## SQLite refuses to boot under a wrong-key DEK

Previously only a PostgreSQL-backed server verified, at start-up, that its Data Encryption Key
(DEK) is the DEK the database is actually encrypted under. A SQLite-backed server did not: a
populated SQLite database could be started under a different (wrong) DEK, after which new rows were
written under the second DEK and the rows written under the first became undecryptable once its key
set was gone.

From this release a SQLite-backed server performs the same check PostgreSQL already did:

- **New/empty database:** unchanged — the first boot records this DEK as the database's DEK.
- **Existing database upgraded to this release:** the first boot records this DEK's fingerprint as
  the database's DEK **only after** confirming this DEK can decrypt the newest encrypted secret
  version. There is no change to the `dek.key` file format; an existing key set loads unchanged and
  self-seeds. If this server's DEK cannot decrypt the database's own data, it refuses to start
  rather than seed a wrong epoch.
- **Wrong key set:** a server whose DEK is not the DEK the database is encrypted under now refuses
  to start, with an error that reports the two DEK *fingerprints* (HMACs, never key material) and
  tells you to restore the correct key files (`dek.key`, `kek.salt`) for this database — from the
  backup those keys were taken with, or by restoring the database and its key set together from one
  `keyorix-server admin backup` archive. Nothing secret is printed.

What has **not** changed: a SQLite DEK rotation (`keyorix-server admin encryption rotate`) keeps the
epoch consistent automatically, in the same transaction as the re-encryption, so a normal rotation
followed by a restart is accepted. A legitimate restore is unaffected: `admin restore` installs the
archive's database image and its key files together, so the restored epoch always matches the
restored keys. There is no runtime write-fence on SQLite (that remains PostgreSQL-only, since SQLite
is single node).

If you hit the refusal after an operator mistake (restored an old database but kept newer keys, or
copied the wrong key directory), start the server with the key set that matches the database — this
is the check doing its job, catching a mismatched key/database pair before it corrupts data.
