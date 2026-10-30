; KIND: mutant
; EXPECT: sat
; `all` rule with the `any` direction (forall j exists i): a parent clause that subsumes no
; child clause is silently dropped. sat = caught.
(assert IND)
(assert ANYRULE)
(assert allChildAccepts)
(assert allParentRejects)
(check-sat)
