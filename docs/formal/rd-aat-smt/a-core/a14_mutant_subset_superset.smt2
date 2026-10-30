; KIND: mutant
; EXPECT: sat
; Mutant: allowed-set direction reversed.
(assert (sub pS cS))
(assert (and (isArr x) (sub (elems x) cS)))
(assert (not (and (isArr x) (sub (elems x) pS))))
(check-sat)
