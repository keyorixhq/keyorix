- **INV-KSYNC-fetch-scope-fail-closed** The scope the server attaches to a secret is
  checked, not trusted, at both steps of a fetch: a `resolveID` list entry matching the
  requested name must itself carry the requested `project_id` and `environment_id`, and
  a `fetchValue` response must carry back the exact `id`, `project_id` and
  `environment_id` that were asked for. An entry or value naming a different project,
  environment, or id — or omitting one — is refused with a plain error, never
  `ErrUpstreamGone`: a scope the server contradicts is a broken answer, not proof the
  secret was removed, and must not wipe the synced copy. A correctly-scoped entry cannot
  be shadowed by a same-named, wrongly-scoped one earlier or later in the list. This
  guards against a server-side filter or lookup bug, not a malicious server that
  controls the whole response and can stamp any scope on its own answer. Why:
  `resolveID` / `fetchValue` (`keyorix_fetcher.go`). Guard:
  `TestFetcher_ListEntryOutsideScopeFailsClosed`,
  `TestFetcher_ValueOutsideScopeFailsClosed`,
  `TestFetcher_InScopeResponseStillDelivers` (`internal/k8ssync`).
