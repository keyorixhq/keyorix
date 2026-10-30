; KIND: proof
; EXPECT: unsat sat
; The pinned pre-publication rules (omitted-key rule also applied to "*") are sound too:
; they are strictly stronger than the published rules. Recorded so the change is shown to be a
; relaxation that needed a new proof (c01), not a tightening.
(assert PINNED)
(assert childAccepts)
(push)
(assert parentRejects)
(check-sat)
(pop)
(check-sat) ; non-vacuity
