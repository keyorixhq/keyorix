### Fixed

- Core authorization refusals (the "permission denied" and "not authorized" family, plus the SoD, risk-exception, machine privilege ceiling and share-management refusals) now match a single sentinel, `core.ErrPermissionDenied`, so a caller can map them to 403 with `errors.Is` instead of matching translated text. The refusal text is unchanged. The bulk-suspend skip check uses the sentinel instead of the translated text.
