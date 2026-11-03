### Fixed
- **Web build no longer leaks `tailwindcss.com` into air-gapped deployments.** Tailwind v4's generated CSS carries a `/*! tailwindcss v4.3.3 | MIT License | https://tailwindcss.com */` banner, which tripped the air-gap guard (`TestAirgapServedMarkupNamesNoExternalHost`) on any PR that triggered a web build check. A small PostCSS plugin now strips that banner comment from generated CSS only; license banners for other JS dependencies are untouched.

### Internal
- **Regenerated `web/src/types/api-generated.ts` against `openapi.yaml`.** The checked-in file was stale relative to `main`, failing the "Generated API types are fresh" Web CI step on every PR.
