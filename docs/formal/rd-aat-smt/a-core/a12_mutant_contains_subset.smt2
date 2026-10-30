; KIND: mutant
; EXPECT: sat
; Mutant: required-set direction reversed.
(assert (sub cS pS))
(assert (and (isArr x) (sub cS (elems x))))
(assert (not (and (isArr x) (sub pS (elems x)))))
(check-sat)
