; KIND: proof
; EXPECT: unsat sat
; range under range: bounds at least as tight, equal bound not inclusive where the parent is exclusive, missing child bound only if the parent bound is missing.
(assert (and (minTighter phasMin pmin pincMin chasMin cmin cincMin) (maxTighter phasMax pmax pincMax chasMax cmax cincMax)))
(assert (cRange x))
(push)
(assert (not (pRange x)))
(check-sat)
(pop)
(check-sat) ; non-vacuity: rule + child acceptance are satisfiable
