; KIND: mutant
; EXPECT: sat
; Key rules evaluated on the maps as written (no empty-map normalisation at 4p2) while 6b
; normalises: an empty child map passes the rules but accepts any argument. Widening found.
(assert (and (R1f pstar) R2 R3 (R4f cstar) (R5f pstar cstar) P4))
(assert childAccepts)
(assert parentRejects)
(check-sat)
(get-value (pstar cstar pS cS wPN wPOPT wCN wCOPT wPRESENT wPSAT wCSAT))
