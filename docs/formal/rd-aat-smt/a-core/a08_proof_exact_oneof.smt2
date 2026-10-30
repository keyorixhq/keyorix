; KIND: proof
; EXPECT: unsat sat
; exact under one_of: the value is a member of the parent values.
(assert (select pS cv))
(assert (= x cv))
(push)
(assert (not (select pS x)))
(check-sat)
(pop)
(check-sat) ; non-vacuity: rule + child acceptance are satisfiable
