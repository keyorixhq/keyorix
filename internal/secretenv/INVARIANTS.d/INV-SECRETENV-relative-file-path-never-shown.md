- **INV-SECRETENV-relative-file-path-never-shown** For a RELATIVE secret-file path (which
  may itself be the secret, e.g. `KEYORIX_DB_PASSWORD_FILE=hunter2`), neither
  `DescribeFile(label, path)` nor `FileError.Error()` ever contains the path value; only the
  `"(a relative path, not shown…)"` form appears. Absolute paths are shown by design. Why:
  `describe.go` `RelativePathNotShown` / `DescribeFile` doc (REVIEW-1 F4). Guard:
  `FuzzDescribeFileNoRelativePathLeak` (a canary placed only in the path must be absent from
  the output for every relative path). Does NOT cover the out-of-package copies (cli
  `describeSecretFile`, entrypoint `_rs_describe`) -- their own equality tests do -- nor the
  secret VALUE (file-content) non-disclosure, which is the read-site's.
