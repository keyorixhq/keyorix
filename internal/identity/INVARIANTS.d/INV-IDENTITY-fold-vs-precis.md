- **INV-IDENTITY-fold-vs-precis** `NewFoldedName`'s fold (`foldedProfile` = precis
  Freeform LowerCase+NFC) may disagree with the RFC 8265 `precis.UsernameCaseMapped`
  profile an external IdP/SCIM client uses ONLY in the documented, allowlisted ways:
  Keyorix accepts strings UsernameCaseMapped rejects (deliberately permissive Freeform —
  spaces, ligatures, etc.), and Keyorix keeps distinct two strings UsernameCaseMapped
  equates by NFKC width mapping (fullwidth `ＡＤＭＩＮ` vs `admin`). Any OTHER equality or
  acceptance divergence — in particular Keyorix REJECTING a username RFC 8265 accepts, or
  an unexplained equality split — is a fold bug with account-collision/shadow-admin
  consequences and must fail. Why: DF1, #1642 normalization boundary. Guard:
  `FuzzIdentityFoldVsPrecis` + `TestFoldCompare_RedGreen` + `TestFoldDiffAllowlistNoDead`
  (`internal/identity`).
