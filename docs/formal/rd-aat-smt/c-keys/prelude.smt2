; Part C prelude: constraint-map key rules of draft-niyikiza-oauth-attenuating-agent-tokens-02.
; Sources: Section 3.3 (closed world, `optional`, `"*"`, empty map = {"*": wildcard}),
; Section 4.5 (the four key bullets + "for each key named in both maps"), Section 8 steps
; 4p2-4p4 (verifier) and 6b (invocation check). See ../README.md.
;
; Universal over the set of argument names: Key is an uninterpreted sort, so a proof (unsat)
; holds for maps naming any number of keys, not for a fixed k1..k3. `"*"` is not a Key: it is
; the map-level flag pstar/cstar (an argument literally named "*" is unnamed, Section 3.3).
; A `"*"` entry must be a wildcard with no `optional` member, so it has no value predicate and
; no optional flag.
;
; Each case file is appended to this prelude:  cat prelude.smt2 c01_*.smt2 | z3 -in

(set-option :produce-models true)

(declare-sort Key 0)   ; argument names other than "*"
(declare-sort Val 0)   ; argument values; equal iff equal JCS serialisation

; Parent map P and child (derived) map C, as written (before normalisation).
(declare-fun pn (Key) Bool)          ; P names key k
(declare-fun popt (Key) Bool)        ; P marks k optional
(declare-const pstar Bool)           ; P contains "*"
(declare-fun psat (Key Val) Bool)    ; P's constraint for k accepts value v
(declare-fun cn (Key) Bool)
(declare-fun copt (Key) Bool)
(declare-const cstar Bool)
(declare-fun csat (Key Val) Bool)

; Normalisation (Section 3.3, steps 4p2 and 6b): an empty map is {"*": wildcard}.
(declare-const pS Bool)
(declare-const cS Bool)
(assert (= pS (or pstar (forall ((k Key)) (not (pn k))))))
(assert (= cS (or cstar (forall ((k Key)) (not (cn k))))))

; One invocation: which arguments are present and their values.
(declare-fun present (Key) Bool)
(declare-fun val (Key) Val)

; Step 6b, closed world, per argument name: a present argument must satisfy the map's
; constraint for it, or the map's "*" (a wildcard: any value) if the map does not name it,
; else DENY; a named, required argument must be present.
(define-fun accP ((k Key)) Bool
  (and (=> (present k) (ite (pn k) (psat k (val k)) pS))
       (=> (and (pn k) (not (popt k))) (present k))))
(define-fun accC ((k Key)) Bool
  (and (=> (present k) (ite (cn k) (csat k (val k)) cS))
       (=> (and (cn k) (not (copt k))) (present k))))

(define-fun childAccepts () Bool (forall ((k Key)) (accC k)))
; The parent rejects the invocation at some argument name kw (Skolem witness).
(declare-const kw Key)
(define-fun parentRejects () Bool (not (accP kw)))

; ---- The key rules, parameterised by which "*" flags they read (normalised or raw) ----
; R1 (4.5 bullet 1, 4p2 clause 1): every key the child names is named by the parent,
;    unless the parent contains "*".
(define-fun R1f ((ps Bool)) Bool (forall ((k Key)) (=> (cn k) (or (pn k) ps))))
; R2 (4.5 bullet 2, 4p3): a key the parent requires stays required in the child.
(define-fun R2f () Bool
  (forall ((k Key)) (=> (and (cn k) (pn k) (not (popt k))) (not (copt k)))))
; R3 (4.5 bullet 3 first condition, 4p2 clause 2): the child may omit a key OTHER THAN "*"
;    that the parent names only if the parent marks it optional.
(define-fun R3f () Bool (forall ((k Key)) (=> (and (pn k) (not (cn k))) (popt k))))
; R4 (4.5 bullet 3 second condition, 4p2 clause 2): ... and only if the child map does not
;    contain "*".
(define-fun R4f ((cs Bool)) Bool (forall ((k Key)) (=> (and (pn k) (not (cn k))) (not cs))))
; R5 (4.5 bullet 4, 4p2 clause 3): the child contains "*" only if the parent does.
(define-fun R5f ((ps Bool) (cs Bool)) Bool (=> cs ps))

(define-fun R1 () Bool (R1f pS))
(define-fun R2 () Bool R2f)
(define-fun R3 () Bool R3f)
(define-fun R4 () Bool (R4f cS))
(define-fun R5 () Bool (R5f pS cS))

; P4 (4.5 "at least as restrictive", 4p4): for a key both maps name, the child's constraint
; is subsumed by the parent's. Assumed here as its semantic consequence (child accepts v =>
; parent accepts v), which is what parts A and B prove for the structural relation. A key the
; child names only under the parent's "*" is compared with a wildcard, which subsumes anything,
; so it needs no hypothesis.
(define-fun P4 () Bool
  (forall ((k Key) (v Val)) (=> (and (cn k) (pn k) (csat k v)) (psat k v))))

; The pinned pre-publication copy (tenuo de8cc33) had no "other than \"*\"" carve-out: the
; omitted-key rule applied to "*" too. A "*" entry can never be marked optional, so under that
; wording a child whose (normalised) map drops the parent's "*" is always refused.
(define-fun R3pinned () Bool (and R3f (not (and pS (not cS)))))

(define-fun PUBLISHED () Bool (and R1 R2 R3 R4 R5 P4))
(define-fun PINNED () Bool (and R1 R2 R3pinned R4 R5 P4))

; Witness readout for satisfiable (widening) cases.
(define-fun wPN () Bool (pn kw))
(define-fun wPOPT () Bool (popt kw))
(define-fun wCN () Bool (cn kw))
(define-fun wCOPT () Bool (copt kw))
(define-fun wPRESENT () Bool (present kw))
(define-fun wPSAT () Bool (psat kw (val kw)))
(define-fun wCSAT () Bool (csat kw (val kw)))
