### Testing
- **Injection-class fuzzing of outbound formatting (ML1).** Added five
  structural-equality fuzz targets, each parsing produced output with an
  independent parser: `FuzzMailSetupLinkInjection` (`internal/delivery`) and
  `FuzzNotifyEmailInjection` (`internal/notifychan`) assert that CRLF/header or
  MIME bytes in recipient/subject/display-name/body can never add a header,
  recipient or MIME part to a go-mail message (net/mail + mime/multipart oracle);
  `FuzzSIEMEventJSONForging` (`internal/audit/siem`) asserts an audit event always
  serialises to exactly one JSON line/object (no newline/delimiter log-forging);
  `FuzzSecretTemplateRenderStructure` (`internal/secrettemplate`) asserts a
  resolved secret value cannot inject a JSON key or an extra `.env` line;
  `FuzzI18nLocalizeFormat` (`internal/i18n`) asserts go-i18n never re-parses
  `TemplateData` as template source and never panics. Each oracle is red/green
  proven. No production code changed; no injection vulnerability found.
