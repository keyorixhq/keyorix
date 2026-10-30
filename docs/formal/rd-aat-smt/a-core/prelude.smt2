; Part A prelude: the core subsumption table of draft-02 Section 4.5 (depth-1 constraints).
; Each case states one table row as the structural rule, then asks for a value the child
; accepts and the parent rejects. Universal over every parameter (bounds, inclusivity flags,
; value sets, the argument).
;
; Val: JSON values, equal iff equal JCS serialisation (Section 3.4). Arrays in `one_of`,
; `not_one_of`, `contains`, `subset` and array arguments are sets of Val ((Array Val Bool));
; the proofs therefore also cover infinite sets, a superset of the finite arrays a token holds.
; Numbers: `range` bounds and numeric arguments are Real. Every admissible JSON number has an
; exact double value and double comparison of finite values equals real comparison, so a
; proof over Real covers them (admissibility itself is not modelled, see README).
;
;   cat prelude.smt2 a01_*.smt2 | z3 -in

(set-option :produce-models true)

(declare-sort Val 0)
(declare-fun isNum (Val) Bool)
(declare-fun num (Val) Real)
(declare-fun isArr (Val) Bool)
(declare-fun elems (Val) (Array Val Bool))   ; element set of an array value

(define-fun sub ((A (Array Val Bool)) (B (Array Val Bool))) Bool
  (forall ((v Val)) (=> (select A v) (select B v))))
(define-fun nonempty ((A (Array Val Bool))) Bool (exists ((v Val)) (select A v)))

; range check: optional bounds, each with an inclusivity flag (default true is one of the two
; values of the flag, so free flags cover the defaults).
(define-fun inRange ((x Real) (hasMin Bool) (mn Real) (incMin Bool)
                     (hasMax Bool) (mx Real) (incMax Bool)) Bool
  (and (=> hasMin (ite incMin (>= x mn) (> x mn)))
       (=> hasMax (ite incMax (<= x mx) (< x mx)))))

; range-under-range rule for one side (Section 4.5 "range" bullet), lower bound:
; parent bound present => child bound present and (strictly inside, or equal and not
; inclusive where the parent is exclusive).
(define-fun minTighter ((phas Bool) (pmin Real) (pinc Bool) (chas Bool) (cmin Real) (cinc Bool)) Bool
  (=> phas (and chas (or (> cmin pmin) (and (= cmin pmin) (not (and cinc (not pinc))))))))
(define-fun maxTighter ((phas Bool) (pmax Real) (pinc Bool) (chas Bool) (cmax Real) (cinc Bool)) Bool
  (=> phas (and chas (or (< cmax pmax) (and (= cmax pmax) (not (and cinc (not pinc))))))))

(declare-const x Val)      ; the argument value
(declare-const pv Val)     ; parent exact value
(declare-const cv Val)     ; child exact value
(declare-const pS (Array Val Bool))   ; parent set (values / excluded / required / allowed)
(declare-const cS (Array Val Bool))   ; child set
(declare-const phasMin Bool) (declare-const pmin Real) (declare-const pincMin Bool)
(declare-const phasMax Bool) (declare-const pmax Real) (declare-const pincMax Bool)
(declare-const chasMin Bool) (declare-const cmin Real) (declare-const cincMin Bool)
(declare-const chasMax Bool) (declare-const cmax Real) (declare-const cincMax Bool)

(define-fun pRange ((v Val)) Bool
  (and (isNum v) (inRange (num v) phasMin pmin pincMin phasMax pmax pincMax)))
(define-fun cRange ((v Val)) Bool
  (and (isNum v) (inRange (num v) chasMin cmin cincMin chasMax cmax cincMax)))
