; KIND: proof
; EXPECT: unsat sat
; one_of under one_of: non-empty subset of the parent values.
(assert (and (nonempty cS) (sub cS pS)))
(assert (select cS x))
(push)
(assert (not (select pS x)))
(check-sat)
(pop)
(check-sat) ; non-vacuity: rule + child acceptance are satisfiable
