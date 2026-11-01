; KIND: proof
; EXPECT: unsat sat
; contains under contains: required set is a superset of the parent required set.
(assert (sub pS cS))
(assert (and (isArr x) (sub cS (elems x))))
(push)
(assert (not (and (isArr x) (sub pS (elems x)))))
(check-sat)
(pop)
(check-sat) ; non-vacuity: rule + child acceptance are satisfiable
