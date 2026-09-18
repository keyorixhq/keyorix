/**
 * @name Fuzz-harness targets: untrusted input reaching a dangerous sink, by sink kind
 * @description Lists (function-to-fuzz, sink-kind, source, sink) tuples where remotely-controlled
 *              input reaches a parser / authz / crypto / format-or-log sink. The output is a
 *              TARGET LIST for the autofuzzgen SAST-guided emitter
 *              (scripts/fuzzing/autofuzzgen): it decides WHERE to place a sound invariant
 *              harness by static data-flow rather than a human's memory, and the sink kind
 *              chooses the invariant family. This is NOT an alert — every row is a fuzzing lead
 *              to review, emit a skeleton for, fill the oracle, and red-proof before it becomes a
 *              real target. Deliberately name-pattern based for the authz/crypto/format sinks
 *              (like this pack's other queries' isBoundingWrapperCall / isValidationCall), since
 *              these guards have no single shared type to hook into.
 * @kind path-problem
 * @problem.severity recommendation
 * @id go/keyorix-fuzz-harness-targets
 * @tags fuzzing
 *       maintainability
 */

import go

/** A structured-input decode/parse sink: the whole parser bug family lives on these. */
predicate parserSink(DataFlow::CallNode call, string kind) {
  kind = "parser" and
  (
    call.getTarget().hasQualifiedName("encoding/json", ["Unmarshal", "NewDecoder"]) or
    call.getTarget().hasQualifiedName("encoding/xml", ["Unmarshal", "NewDecoder"]) or
    call.getTarget().hasQualifiedName("encoding/asn1", "Unmarshal") or
    call.getTarget().hasQualifiedName("encoding/pem", "Decode") or
    call.getTarget().hasQualifiedName("crypto/x509", ["ParseCertificate", "ParseCertificates"]) or
    call.getTarget().hasQualifiedName("net/url", ["Parse", "ParseRequestURI"]) or
    call.getTarget().hasQualifiedName("compress/gzip", "NewReader") or
    call.getTarget().hasQualifiedName("archive/tar", "NewReader") or
    call.getTarget().hasQualifiedName("encoding/csv", "NewReader")
  )
}

/** An authorization decision — untrusted input reaching one wants a fail-closed differential. */
predicate authzSink(DataFlow::CallNode call, string kind) {
  kind = "authz" and
  call.getTarget().getName().regexpMatch("(?i).*(authorize|requirepermission|haspermission|checkpermission|allows).*")
}

/** A crypto open/unwrap/verify — wants a tamper / round-trip / key-commitment oracle. */
predicate cryptoSink(DataFlow::CallNode call, string kind) {
  kind = "crypto" and
  call.getTarget().getName().regexpMatch("(?i).*(unwrap|decrypt|aeadopen|verifymac|hmacequal).*")
}

/** An audit/log/template emit — wants an injection (control-char / formula / forged-line) oracle. */
predicate formatSink(DataFlow::CallNode call, string kind) {
  kind = "format" and
  call.getTarget().getName().regexpMatch("(?i).*(writeaudit|auditlog|rendertemplate|templateexecute).*")
}

/** Any recognised sink, tagged with its kind. */
predicate taggedSink(DataFlow::CallNode call, string kind) {
  parserSink(call, kind) or
  authzSink(call, kind) or
  cryptoSink(call, kind) or
  formatSink(call, kind)
}

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode call | taggedSink(call, _) | sink = call.getAnArgument())
  }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module Flow = TaintTracking::Global<Config>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink, DataFlow::CallNode call, string kind
where
  Flow::flowPath(source, sink) and
  taggedSink(call, kind) and
  sink.getNode() = call.getAnArgument()
select sink, source, sink,
  "FUZZ-TARGET kind=" + kind + " fn=" + sink.getNode().getEnclosingCallable().getName() +
    " — untrusted input reaches a " + kind + " sink; emit a " + kind + " invariant harness."
