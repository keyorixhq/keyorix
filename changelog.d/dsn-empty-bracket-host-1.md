### Testing
- **DSN host extraction keeps an empty bracketed host (`host=[]`) as a candidate.** The host-list
  splitter stripped the brackets to an empty string and every caller dropped it, so the host guard
  saw no host for a DSN whose host the Postgres driver still reads. The entry is now kept as
  written; `FuzzDSNHostsCoverDriverHosts` covers it with a regression seed.
