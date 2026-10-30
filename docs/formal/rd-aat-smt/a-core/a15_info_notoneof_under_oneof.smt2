; KIND: info
; EXPECT: sat
; not_one_of under one_of (invalid in the table): no rule over the two sets alone makes it sound, a value outside both sets is accepted by the child. sat = shown unsound, which is why the draft rejects the pair.
(assert true)
(assert (not (select cS x)))
(assert (not (select pS x)))
(check-sat)
