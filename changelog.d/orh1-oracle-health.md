### Testing

- **Oracle health: a planted-defect suite for the fuzz harnesses.** `scripts/fuzzing/oracle-health/oracle-health.sh` runs each harness on its seed corpus unmodified and again with one planted defect (one patch per entry), and fails when a control is red or a harness stays green on its defect. Ten entries (PG interrupted upgrade, request-echo canary, hostile O4/O7, storage differential, audit completeness, bounded work, authzdiff). Scripts, entries and bats tests only; meant for the nightly host, no workflow added. Two harnesses found blind to their plant: #4739, #4740.
