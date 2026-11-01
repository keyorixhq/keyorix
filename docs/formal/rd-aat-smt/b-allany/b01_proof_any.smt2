; KIND: proof
; EXPECT: unsat sat
; Published `any` rule (forall j exists i, no one-to-one matching) is sound: a child `any`
; never accepts a value every parent clause rejects. Second query (non-vacuity, the J.16.7
; shape): the rule admits a split, two distinct child clauses subsumed by the same, single
; parent clause, together with an accepted value.
(assert IND)
(assert ANYRULE)
(assert anyChildAccepts)
(push)
(assert anyParentRejects)
(check-sat)
(pop)
(push)
(declare-const j1 CJ)
(declare-const j2 CJ)
(declare-const i1 PI)
(assert (and (distinct j1 j2) (m j1 i1) (m j2 i1) (forall ((i PI)) (= i i1))))
(check-sat)
(pop)
