### Testing
- **Egress guard wiring is now fuzzed per site.** Eight new test-only fuzz targets (`FuzzJWKSTransportEgressParity`, `FuzzOIDCDiscoveryTransportEgressParity`, `FuzzAzureGraphTransportEgressParity`, `FuzzConnect{Vault,Azure,AWS}TransportEgressParity`, `FuzzAzureKMSTransportEgressParity`, `FuzzAzureKMSResolverRebinding`) dial each guarded transport with one address in ten encodings (IPv4-mapped, NAT64, 6to4, Teredo, zone-suffixed link-local, metadata addresses) and compare against an independent reference in `internal/fuzzutil/egressref`; the oracles are red-proofed by planted bypasses in that package's tests.

### Documentation
- `docs/security/egress-inventory.md` gains a per-site table (who supplies the destination, which guard sits in front, redirect policy, fuzz coverage), the documented differences between the guard tiers, and two findings (F1 tracked privately, F2 #4738).
