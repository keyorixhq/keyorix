/**
 * @name Outbound HTTP request built from an unvalidated destination or sent without a redirect guard
 * @description An outbound HTTP request (http.Client.Do/Get/Post/PostForm, the package-level
 *              http.Get/http.Post/http.PostForm/http.Head convenience functions, or
 *              http.DefaultClient) is sent to a URL/host read from a config- or
 *              request-derived field (DSN, webhook/callback URL, admin endpoint, ...)
 *              where either:
 *               (a) no recognised SSRF-guard call (a private/link-local/loopback/allowlist
 *                   check, by this repo's naming convention) is ever applied to that same
 *                   field anywhere in the codebase, so the destination is never validated
 *                   before use; or
 *               (b) the http.Client used to send the request has no CheckRedirect set, so
 *                   even a destination that IS validated at write time can be bounced by a
 *                   3xx response to an internal host (e.g. cloud IMDS) at request time.
 *              Both are recurring instances of CWE-918 in this codebase (GRPC-006, SSRF-004,
 *              and the alert-escalation webhook dispatcher SSRF/redirect fixes).
 * @kind problem
 * @problem.severity warning
 * @id go/keyorix-ssrf-unvalidated-outbound-request
 * @tags security
 *       external/cwe/cwe-918
 */

import go

/**
 * Holds if `call` is a recognised SSRF-guard / destination-validation call by this
 * codebase's naming convention: a function whose name mentions "ssrf", or that reads
 * like "validate...URL/Host/DSN/Endpoint/Webhook" (in either direction, e.g. also
 * "urlValidator" -- this repo's notification_channels.go calls its guard through a
 * `urlValidator func(string) error` local variable, defaulting to validateWebhookURL,
 * so a validator/checker-style name is recognised regardless of word order), or that
 * reads like an is-private/internal/loopback/disallowed-address check
 * (validateAdminDSNHost, validateWebhookURL, isChannelDisallowedIP, isPrivateIP,
 * parseDSNHost feeding one of those; noEscalationRedirect and friends are handled
 * separately as CheckRedirect funcs, not here). Deliberately name-pattern based (like
 * the two existing custom queries' isBoundingWrapperCall/isLstatCall) rather than
 * modelling each guard's internals -- this repo has several independently-implemented
 * guards with no shared type or interface to hook into.
 *
 * Matches against three name sources per call, not just the declared target: a direct
 * call's target name, the *statically resolved* callee when the call goes through a
 * local function-valued variable (`getACalleeIncludingExternals`, which is exactly
 * this repo's `urlValidator(ch.URL)` shape -- `Function.getTarget()` alone returns no
 * result for a call through a variable), and the syntactic callee name itself
 * (`getCalleeName`, which for an indirect call is the variable's own name, e.g.
 * "urlValidator" or "webhookURLValidator").
 */
predicate isValidationCall(DataFlow::CallNode call) {
  exists(string name |
    name = call.getTarget().getName()
    or
    name = call.getACalleeIncludingExternals().asFunction().getName()
    or
    name = call.getCalleeName()
  |
    name.toLowerCase().matches("%ssrf%")
    or
    name.toLowerCase().regexpMatch("(?i).*valid.*(url|host|dsn|endpoint|webhook|target).*")
    or
    name.toLowerCase().regexpMatch("(?i)(url|host|dsn|endpoint|webhook|target).*valid.*")
    or
    name.toLowerCase()
        .regexpMatch("(?i)is.*(private|internal|loopback|linklocal|link_local|disallowed).*(ip|host|addr)")
  )
}

/**
 * Holds if `f` is a struct field whose name suggests it holds an outbound request
 * destination -- a URL, host, DSN, or webhook/callback endpoint. This is the same
 * name-pattern approach the two existing queries use for their sources (isReaderOrigin's
 * "Body" field) and sinks (isLstatCall/isPathBasedPermissionCall's os.* names): match
 * the shape of the known vulnerable fields (NotificationChannel.URL, admin_dsn) rather
 * than trying to type-model every possible destination-holding struct.
 */
predicate isDestinationField(Field f) {
  f.getName().toLowerCase().regexpMatch(".*(url|host|endpoint|dsn|webhook|callback).*") and
  // Exclude Go's own net/url.URL.Host field and similar stdlib-shaped noise by name
  // alone would be too broad a net; instead this is narrowed by requiring (in
  // isSource below) that the read actually reaches an HTTP client-request sink, which
  // stdlib-internal Host/URL bookkeeping fields never do on their own.
  not f.getName() = "Scheme"
}

/**
 * Holds if a recognised validation call (isValidationCall) is ever applied directly to
 * a read of field `f` anywhere in the codebase -- i.e. some call site passes `f`'s
 * value straight into a validator, by source-text/node identity of the argument. This
 * models this repo's actual pattern: destination fields are validated once, at
 * create/update (write) time, in a function that is NOT on the same call path as the
 * later read-and-dispatch that sends the request (the two are connected only through
 * storage, which plain dataflow can't see across). Without this, every dispatch-time
 * read of an already-validated field would flood the query with the exact false
 * positives this repo's own SSRF fixes were designed to close (see
 * internal/core/alert_escalation.go's postJSONToURL / dispatchToChannel, guarded by
 * validateWebhookURL at internal/core/notification_channels.go's Create/Update path,
 * not at send time) -- treating "validated somewhere, on this exact field" as a
 * whole-program fact, rather than requiring an in-path barrier, is what keeps this
 * query's negative-control sites (already-fixed GRPC-006/SSRF-004/#1161) silent.
 */
predicate isFieldValidatedAtWriteTime(Field f) {
  exists(DataFlow::CallNode validate |
    isValidationCall(validate) and
    validate.getAnArgument() = f.getARead()
  )
}

/** A destination-shaped field read that is never validated anywhere in the codebase. */
predicate isUnvalidatedDestinationRead(DataFlow::Node source) {
  exists(Field f | isDestinationField(f) and source = f.getARead() and not isFieldValidatedAtWriteTime(f))
}

module UnvalidatedConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { isUnvalidatedDestinationRead(source) }

  predicate isSink(DataFlow::Node sink) { sink = any(Http::ClientRequest r).getUrl() }

  predicate isBarrier(DataFlow::Node node) {
    exists(DataFlow::CallNode v | isValidationCall(v) and node = v.getResult())
  }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module UnvalidatedFlow = TaintTracking::Global<UnvalidatedConfig>;

/**
 * Holds if `sink`'s HTTP request goes out through a client this query can prove has no
 * CheckRedirect set: either one of the package-level convenience functions
 * (http.Get/http.Post/http.PostForm/http.Head, or http.DefaultClient.Do/Get/Post),
 * which always follow redirects under Go's default policy, or a `client.Do/Get/Post/
 * PostForm` call whose receiver flows from a local `&http.Client{...}` literal missing
 * a CheckRedirect key. A receiver of unknown/external provenance (a struct field set
 * up elsewhere, e.g. an injected *http.Client) is deliberately NOT flagged here -- this
 * query can't see whether that client's CheckRedirect was set at its construction
 * site, and guessing "no" would be a false positive, not a finding.
 */
predicate isRedirectUnsafeSink(DataFlow::Node sink) {
  exists(Http::ClientRequest req | sink = req.getUrl() |
    // Package-level http.Get/Post/PostForm/Head: Go's http package always follows
    // redirects here -- there is no per-call CheckRedirect override for these.
    exists(DataFlow::CallNode call, Function fn |
      call = req and
      fn = call.getTarget() and
      not fn instanceof Method
    |
      fn.hasQualifiedName("net/http", ["Get", "Head", "Post", "PostForm"])
    )
    or
    // A client.Do/Get/Post/PostForm/Head method call.
    exists(DataFlow::CallNode call, DataFlow::Node recv |
      call = req and
      recv = call.(DataFlow::MethodCallNode).getReceiver()
    |
      // Receiver is (locally derived from) http.DefaultClient, which this repo never
      // configures a CheckRedirect on (nothing assigns http.DefaultClient.CheckRedirect).
      exists(Variable v | v.hasQualifiedName("net/http", "DefaultClient") |
        DataFlow::localFlow(v.getARead(), recv)
      )
      or
      // Receiver is (locally derived from) a local `&http.Client{...}` literal with no
      // CheckRedirect key.
      exists(CompositeLit lit |
        lit.getTypeExpr().getType().hasQualifiedName("net/http", "Client") and
        DataFlow::localFlow(DataFlow::exprNode(lit), recv) and
        not exists(int i | lit.getKey(i).toString() = "CheckRedirect")
      )
    )
  )
}

from DataFlow::Node sink, string reason
where
  (
    exists(DataFlow::Node source | UnvalidatedFlow::flow(source, sink)) and
    reason =
      "its destination (URL/host/DSN/endpoint field) is never passed to a recognised SSRF-guard validation call anywhere in this codebase"
  )
  or
  (
    isRedirectUnsafeSink(sink) and
    reason =
      "it is sent through an http.Client with no CheckRedirect, so a 3xx response from the destination can bounce it to an internal host regardless of any upfront validation"
  )
select sink, "This outbound HTTP request is unsafe: " + reason + "."
