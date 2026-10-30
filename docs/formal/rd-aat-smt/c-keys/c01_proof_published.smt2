; KIND: proof
; EXPECT: unsat sat
; Published -02 key rules R1-R5 + P4 are sound: no invocation is accepted by the child map
; and rejected by the parent map. Second query (non-vacuity): the case the carve-out opened,
; a child that drops the parent's "*" while naming and receiving an argument, satisfies all
; hypotheses, so the proof covers it.
(assert PUBLISHED)
(assert childAccepts)
(push)
(assert parentRejects)
(check-sat)
(pop)
(push)
(assert (and pS (not cS) (exists ((k Key)) (and (cn k) (present k)))))
(check-sat)
(pop)
