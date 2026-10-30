; KIND: proof
; EXPECT: unsat sat
; Any child under wildcard: the parent accepts every value, so nothing can be rejected.
(assert true)
(assert (select cS x))
(push)
(assert false)
(check-sat)
(pop)
(check-sat) ; non-vacuity: rule + child acceptance are satisfiable
