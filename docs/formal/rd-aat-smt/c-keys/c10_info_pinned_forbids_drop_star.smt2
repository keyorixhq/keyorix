; KIND: info
; EXPECT: unsat sat
; Under the pinned wording no child can drop the parent's "*" (unsat), although 4.5 bullet 4
; says dropping "*" narrows and is allowed: the self-contradiction the published text fixed.
; Under the published rules the same shape is admitted (sat), e.g. parent {} (= {"*"}) and
; child {a: exact 1}.
(push)
(assert PINNED)
(assert (and pS (not cS)))
(check-sat)
(pop)
(push)
(assert PUBLISHED)
(assert (and pS (not cS)))
(check-sat)
(pop)
