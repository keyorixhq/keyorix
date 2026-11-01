; KIND: mutant
; EXPECT: sat
; `any` rule weakened to "some child clause is subsumed by some parent clause"
; (exists j exists i): a widening child clause rides along. sat = caught.
(assert IND)
(assert (exists ((j CJ) (i PI)) (m j i)))
(assert anyChildAccepts)
(assert anyParentRejects)
(check-sat)
