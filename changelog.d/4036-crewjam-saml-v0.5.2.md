### Security
- **Updated `crewjam/saml` to v0.5.2 (GO-2026-6909).** The SAML library now returns an error instead of panicking on a signed assertion without `Subject`, `Conditions` or `SubjectConfirmationData`, and binds `NameID` and the other assertion children to the SAML assertion namespace. It also requires a bearer `SubjectConfirmation` and an `AudienceRestriction`: an IdP that omits either is now rejected at the ACS.

### Testing
- **`FuzzSAMLXMLTransitive`** fuzzes the SAML XML stack and fails on `crewjam/saml` v0.5.1, so a dependency downgrade or regression is caught.
