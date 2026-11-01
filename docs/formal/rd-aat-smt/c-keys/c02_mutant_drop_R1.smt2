; KIND: mutant
; EXPECT: sat
; R1 removed from the published rule set. sat = the checker finds a widening, so R1 is
; load-bearing. Witness: the "*" flags and the parent/child entries at the rejecting key.
(assert (and R2 R3 R4 R5 P4))
(assert childAccepts)
(assert parentRejects)
(check-sat)
(get-value (pstar cstar pS cS wPN wPOPT wCN wCOPT wPRESENT wPSAT wCSAT))
