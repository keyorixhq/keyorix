### Security
- **Admin DSN host validation handles repeated bracket layers.** `SplitDSNHostList` now strips every outer bracket pair, not just one, so a host written with more than one layer reaches `validateAdminDSNHost` in the same normalised form as the driver sees it. `TestAdminDSNHost_DoubleBracketIPv6_Blocked` is the red/green guard; the `FuzzDSNHostsCoverDriverHosts` oracle strips brackets the same way. Closure: `dsn-double-bracket-ipv6-001`.

### Testing
- **Pin repeated-bracket seeds for `FuzzDSNHostsCoverDriverHosts`.** Three seeds (`host=[[::1]]`, `host=[[fe80::1]]`, `host=[[::1]],203.0.113.5`) lock in the driver differential for repeated brackets.
