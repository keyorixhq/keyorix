; KIND: mutant
; EXPECT: sat
; The per-key value subsumption (4p4) removed, key rules kept: widening found. Not one of the
; key rules; listed to show the key rules alone do not carry soundness.
(assert (and R1 R2 R3 R4 R5))
(assert childAccepts)
(assert parentRejects)
(check-sat)
(get-value (pstar cstar pS cS wPN wPOPT wCN wCOPT wPRESENT wPSAT wCSAT))
