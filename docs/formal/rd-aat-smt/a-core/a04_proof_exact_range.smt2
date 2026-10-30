; KIND: proof
; EXPECT: unsat sat
; exact under range: the value is a number the parent range accepts.
(assert (pRange cv))
(assert (= x cv))
(push)
(assert (not (pRange x)))
(check-sat)
(pop)
(check-sat) ; non-vacuity: rule + child acceptance are satisfiable
