; KIND: bug
; EXPECT: sat
; Seeded bug: lower bound compared with >= only, so an inclusive child min equal to an exclusive parent min passes (x = pmin is the widening). The checker must find it.
(assert (and (=> phasMin (and chasMin (>= cmin pmin))) (maxTighter phasMax pmax pincMax chasMax cmax cincMax)))
(assert (cRange x))
(assert (not (pRange x)))
(check-sat)
