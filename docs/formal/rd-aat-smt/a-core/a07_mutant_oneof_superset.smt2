; KIND: mutant
; EXPECT: sat
; Mutant: subset direction reversed.
(assert (and (nonempty cS) (sub pS cS)))
(assert (select cS x))
(assert (not (select pS x)))
(check-sat)
