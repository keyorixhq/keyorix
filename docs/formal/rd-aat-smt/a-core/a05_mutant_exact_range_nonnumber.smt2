; KIND: mutant
; EXPECT: sat
; Mutant: exact under range checks the bounds on num(value) but not that the value is a number.
(assert (inRange (num cv) phasMin pmin pincMin phasMax pmax pincMax))
(assert (= x cv))
(assert (not (pRange x)))
(check-sat)
