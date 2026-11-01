; KIND: bug
; EXPECT: sat
; Seeded bug (a plausible misreading of the carve-out): "the child may omit a parent key if the
; key is optional OR the parent has \"*\"" (the omitted argument "returns under *"). R3 is
; replaced by that weaker rule. The checker must find the widening: parent
; {k: required, "*"}, child names another key, omits k and drops "*"; the child accepts an
; invocation without k that the parent rejects.
(assert (and R1 R2 R4 R5 P4))
(assert (forall ((k Key)) (=> (and (pn k) (not (cn k))) (or (popt k) pS))))
(assert childAccepts)
(assert parentRejects)
(check-sat)
(get-value (pstar cstar pS cS wPN wPOPT wCN wCOPT wPRESENT wPSAT wCSAT))
