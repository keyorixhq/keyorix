; KIND: info
; EXPECT: unsat
; "Union coverage" (each child clause is covered by the union of the parent clauses, the rule
; J.16.8 says a verifier must NOT use) is semantically sound: unsat. So the J.16.8 DENY is a
; decidability / determinism choice of the draft, not a soundness requirement, and no soundness
; model (this one included) can tell a verifier that accepts J.16.8 from one that rejects it.
; Only the vector can. Recorded so nobody cites part B as covering J.16.8.
(assert (forall ((j CJ) (v Val)) (=> (Q j v) (exists ((i PI)) (P i v)))))
(assert anyChildAccepts)
(assert anyParentRejects)
(check-sat)
