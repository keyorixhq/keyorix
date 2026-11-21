- **INV-MW-trusted-proxy-ipv4-mapped-is-ipv4** A `server.http.trusted_proxies` entry written
  as an IPv4-mapped IPv6 address trusts the IPv4 address or network it names, never the IPv6
  network `net.ParseCIDR` makes of the text (`::ffff:1.2.3.4/32` → `::/32`, which holds `::1`).
  Bare `::ffff:a.b.c.d` is the host `a.b.c.d/32`; `::ffff:a.b.c.d/N` with N ≤ 32 is the IPv4
  network `a.b.c.d/N`; N from 33 to 95 has no IPv4 meaning and is dropped (fail closed: that
  peer is untrusted); N ≥ 96 is an ordinary IPv6 network over the mapped range. The rule is
  `rules.NormalizeIPv4MappedCIDR`, shared with the PAT/machine-token encoder, never a second
  implementation. Why: #4520 (a `::1` peer could set X-Forwarded-For/X-Real-IP, which keys the
  per-IP login/MFA limiter and the CIDR allowlists). Guard: `client_ip_trusted_hop_test.go`
  (`TestParseCIDRs_IPv4MappedBareEntryIsSingleHost`, `TestParseCIDRs_IPv4MappedExplicitPrefix`);
  `client_ip_fuzz_test.go` (`FuzzClientIPParsing` oracle (b)).
<!-- section: Rate limiting / abuse resistance -->
