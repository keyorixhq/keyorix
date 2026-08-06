/**
 * @name Unbounded reader passed to json.NewDecoder
 * @description An io.Reader carrying untrusted/remote data (an HTTP response body, a
 *              network connection, process stdin) is passed to json.NewDecoder without
 *              first being bounded by io.LimitReader, http.MaxBytesReader, or this
 *              repo's own maxMessageReader wrapper. The full body is buffered into
 *              memory before any application-level size check ever runs -- a
 *              self-inflicted memory-exhaustion DoS if the remote end (or an
 *              untrusted local process) sends an oversized payload.
 * @kind path-problem
 * @problem.severity warning
 * @id go/keyorix-unbounded-decoder-read
 * @tags security
 *       external/cwe/cwe-400
 */

import go

/**
 * Holds if `call` is one of this codebase's sanctioned size-bounding wrappers around
 * an io.Reader: io.LimitReader, http.MaxBytesReader, or the repo-local
 * newMaxMessageReader (internal/mcp/server.go). The RESULT of any of these is treated
 * as a barrier -- taint from the underlying unbounded reader must not propagate past
 * the wrapping call to whatever consumes the wrapper's return value.
 */
predicate isBoundingWrapperCall(DataFlow::CallNode call) {
  call.getTarget().hasQualifiedName("io", "LimitReader")
  or
  call.getTarget().hasQualifiedName("net/http", "MaxBytesReader")
  or
  call.getTarget().getName() = "newMaxMessageReader"
}

/**
 * Holds if `sink`'s enclosing file is under server/http/handlers/, where
 * server/middleware's MaxBodyBytes middleware already rewrites the incoming
 * request's Body field (`r.Body = http.MaxBytesReader(w, r.Body, limit)`, see
 * server/middleware/body_limit.go) to a bounded reader before any handler ever
 * runs -- a request-lifecycle fact this query's pure dataflow analysis can't see,
 * since the bounding happens in a different function on the same *http.Request
 * earlier in the middleware chain. Excluded to match this repo's existing
 * .semgrep/keyorix-rules.yml scoping for the same reason.
 */
predicate isMiddlewareProtected(DataFlow::Node sink) {
  sink.getFile().getRelativePath().matches("server/http/handlers/%")
}

/**
 * Holds if `source` is a value this query treats as an origin of an unbounded
 * io.Reader: a `.Body` field read (covers *http.Response.Body on an outbound client
 * call -- CodeQL's built-in ActiveThreatModelSource only models the INBOUND
 * *http.Request.Body case, not a response this process's own client received, which
 * is exactly the shape of every real finding this query exists to catch), or an
 * io.Reader-typed function parameter (covers a stdin-fed entrypoint like
 * internal/mcp/server.go's Serve(ctx, r io.Reader, w io.Writer)).
 */
predicate isReaderOrigin(DataFlow::Node source) {
  exists(Field f | f.getName() = "Body" | source = f.getARead())
  or
  exists(DataFlow::ParameterNode p |
    exists(p.getType().getUnderlyingType().(InterfaceType).getMethodType("Read"))
  |
    source = p
  )
}

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { isReaderOrigin(source) }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode call |
      call.getTarget().hasQualifiedName("encoding/json", "NewDecoder") and
      sink = call.getArgument(0) and
      not isMiddlewareProtected(sink)
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    exists(DataFlow::CallNode wrap | isBoundingWrapperCall(wrap) and node = wrap.getResult())
  }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module Flow = TaintTracking::Global<Config>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink, source, sink,
  "This reader carries untrusted data and reaches json.NewDecoder without a size bound (io.LimitReader / http.MaxBytesReader / newMaxMessageReader)."
