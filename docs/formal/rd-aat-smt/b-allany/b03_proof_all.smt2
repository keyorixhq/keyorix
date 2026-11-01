; KIND: proof
; EXPECT: unsat sat
; Published `all` rule (forall i exists j) is sound. Second query (non-vacuity): one child
; clause satisfies two distinct parent clauses and is the only child clause (the draft's
; all([wildcard, wildcard]) -> all([exact(5)]) example), with an accepted value.
(assert IND)
(assert ALLRULE)
(assert allChildAccepts)
(push)
(assert allParentRejects)
(check-sat)
(pop)
(push)
(declare-const j1 CJ)
(declare-const i1 PI)
(declare-const i2 PI)
(assert (and (distinct i1 i2) (m j1 i1) (m j1 i2) (forall ((j CJ)) (= j j1))))
(check-sat)
(pop)
