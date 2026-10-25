---------------------------- MODULE MCOwedAudit ----------------------------
(* Model values for OwedAudit's TLC configurations (the cfg files in this directory). *)
EXTENDS OwedAudit

\* Small: one revocation (two owed rows), one grant, one break-glass activation.
KindSmall == <<"revoke", "widen", "breakglass">>

\* Wide: adds a mixed request (narrow + widen). An ordinary audited write ("write")
\* takes exactly the same action as "widen", so it adds states but no behaviour.
KindWide == <<"revoke", "mixed", "widen", "breakglass">>

\* Bug hunting: the smallest population that exercises each seeded bug.
KindRevokeWiden == <<"revoke", "widen">>
KindMixed == <<"mixed">>
KindRevokeOnly == <<"revoke">>
KindMixedRevoke == <<"mixed", "revoke">>
=============================================================================
