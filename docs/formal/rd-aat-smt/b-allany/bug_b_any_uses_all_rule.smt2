; KIND: bug
; EXPECT: sat
; Seeded bug: the `any` check implemented with the `all` matching direction (forall i exists
; j: every parent clause subsumes some child clause), i.e. the two loops of check_all /
; check_any swapped. A child `any` can then add an unsubsumed clause. The checker must find it.
(assert IND)
(assert ALLRULE)
(assert anyChildAccepts)
(assert anyParentRejects)
(check-sat)
