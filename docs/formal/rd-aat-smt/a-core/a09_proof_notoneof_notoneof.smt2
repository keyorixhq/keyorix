; KIND: proof
; EXPECT: unsat sat
; not_one_of under not_one_of: excluded set is a superset of the parent excluded set.
(assert (sub pS cS))
(assert (not (select cS x)))
(push)
(assert (select pS x))
(check-sat)
(pop)
(check-sat) ; non-vacuity: rule + child acceptance are satisfiable
