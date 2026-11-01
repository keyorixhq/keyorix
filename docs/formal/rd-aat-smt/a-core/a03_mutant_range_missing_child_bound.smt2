; KIND: mutant
; EXPECT: sat
; Mutant: a child range may omit a bound the parent has (only bounds present on both sides compared).
(assert (and (=> (and phasMin chasMin) (or (> cmin pmin) (and (= cmin pmin) (not (and cincMin (not pincMin)))))) (maxTighter phasMax pmax pincMax chasMax cmax cincMax)))
(assert (cRange x))
(assert (not (pRange x)))
(check-sat)
