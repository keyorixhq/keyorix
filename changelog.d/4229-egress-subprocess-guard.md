### Security
- **Egress inventory now covers subprocesses.** `TestEgressSubprocessSitesAreInventoried`
  (report-only for now) fails when shipped Go code starts a process (`os/exec`, `syscall.Exec`,
  `os.StartProcess`) at a place that has no row in the new "Subprocess call sites" table of
  `docs/security/egress-inventory.md`. Each row records the class, what runs, who sets the
  command line and whether it can reach the network.
