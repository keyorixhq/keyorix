; KIND: proof
; EXPECT: unsat sat
; subset under subset: allowed set is a subset of the parent allowed set.
(assert (sub cS pS))
(assert (and (isArr x) (sub (elems x) cS)))
(push)
(assert (not (and (isArr x) (sub (elems x) pS))))
(check-sat)
(pop)
(check-sat) ; non-vacuity: rule + child acceptance are satisfiable
