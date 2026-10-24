### Internal

- CodeQL gate (`scripts/ci/codeql-gate.sh`): every new high-severity result now prints rule id, security-severity, file:line, the message and the first code-flow step in the log text, and the gate writes a table to the job summary. Tests use a real SARIF excerpt and real alert lists from main.
