; Part B prelude: `all` / `any` clause matching, draft-02 Section 4.5 (and step 4p4).
; Universal over the number of clauses: parent clause indices (PI) and child clause indices
; (CJ) are uninterpreted sorts, so a proof holds for every pair of clause lists. SMT sorts are
; non-empty, which matches the draft (an empty `all`/`any` is not well-formed, steps 3n/4o).
;
; m(j,i) = "the recursive structural check says child clause j is subsumed by parent clause i".
; Inductive step: assuming m is sound one level down (IND), the combinator rule is sound one
; level up. Depth 1 is part A; depth is bounded by MAX_CONSTRAINT_DEPTH, so induction on depth
; covers every well-formed tree.
;
;   cat prelude.smt2 b01_*.smt2 | z3 -in

(set-option :produce-models true)

(declare-sort PI 0)
(declare-sort CJ 0)
(declare-sort Val 0)
(declare-fun P (PI Val) Bool)   ; parent clause i accepts v
(declare-fun Q (CJ Val) Bool)   ; child clause j accepts v
(declare-fun m (CJ PI) Bool)    ; child clause j ⊑ parent clause i (structural)

(define-fun IND () Bool (forall ((j CJ) (i PI) (v Val)) (=> (and (m j i) (Q j v)) (P i v))))

; Published matching rules.
; any: for each derived clause there is a parent clause that subsumes it (forall j exists i).
;      No one-to-one assignment: several child clauses may map to one parent clause (a split).
(define-fun ANYRULE () Bool (forall ((j CJ)) (exists ((i PI)) (m j i))))
; all: every parent clause subsumes at least one derived clause (forall i exists j).
(define-fun ALLRULE () Bool (forall ((i PI)) (exists ((j CJ)) (m j i))))

; One argument value x.
(declare-const x Val)
(declare-const jw CJ)   ; witness child clause (any accepts x via clause jw)
(declare-const iw PI)   ; witness parent clause (all rejects x at clause iw)
(define-fun anyChildAccepts () Bool (Q jw x))
(define-fun anyParentRejects () Bool (forall ((i PI)) (not (P i x))))
(define-fun allChildAccepts () Bool (forall ((j CJ)) (Q j x)))
(define-fun allParentRejects () Bool (not (P iw x)))
