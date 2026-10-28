- **INV-HTTP-airgap-webui-no-external-hosts** The web UI shell, its CSS and `/swagger/` are served
  entirely from the binary: every file the web build ships (`/assets`, `/fonts`, `/favicon.svg`, ...)
  is routed by `registerWebUI` at its own path with its own Content-Type, and no page the server hands
  out names a third-party host (swagger-ui is vendored under `handlers/swaggerui`, pinned by SHA-256, with
  the online validator off). Otherwise an air-gapped install silently loses fonts or docs, and an
  authenticated API host sends the operator's browser to a third party. Why: AIRGAP-WEBUI-1
  (`/fonts/*` fell through to the SPA shell; `swagger.go` loaded unpkg.com). Guard:
  `TestWebUIServesEveryDistFile`, `TestAirgapServedMarkupNamesNoExternalHost` (HTML/CSS and Go markup
  literals; report-only until promoted, see `docs/guard-rollout.d`), `handlers`
  `TestSwaggerUIVendoredFilesArePinned` and `TestSwaggerPage_NoExternalHost`. Not covered: a runtime
  `fetch()`/`import()` of a third-party URL inside a JS bundle (Vite output or the vendored swagger-ui).
