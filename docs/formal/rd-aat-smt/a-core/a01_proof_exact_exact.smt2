; KIND: proof
; EXPECT: unsat sat
; exact under exact: same value.
(assert (= cv pv))
(assert (= x cv))
(push)
(assert (not (= x pv)))
(check-sat)
(pop)
(check-sat) ; non-vacuity: rule + child acceptance are satisfiable
