; KIND: mutant
; EXPECT: sat
; Mutant: excluded-set direction reversed.
(assert (sub cS pS))
(assert (not (select cS x)))
(assert (select pS x))
(check-sat)
