# Driver protocol

Each SDK driver is a long-lived process. The orchestrator writes one line per SDK call to its stdin and
reads exactly one JSON line from its stdout.

Request: tab-separated fields

    OP <TAB> hex(base_url) <TAB> hex(token) <TAB> timeout_ms <TAB> arg1 <TAB> arg2 ...

- `OP`: `construct` (base_url is the literal under test, no request is made), `health`, `login`
  (args: username, password), `list_secrets` (environment), `get_secret` (name, environment),
  `list_projects`, `create_project` (name, description), `list_environments` (project id as decimal text).
- every text field is the hex of its UTF-8 bytes, `~` stands for null/absent (hex avoids any escaping
  problem and needs no JSON parser in the Java driver)
- `timeout_ms` 0 means the SDK default; otherwise the SDK's own timeout facility is used

Response: one JSON object

- `{"ok":true,"value":V,"ms":N}` with V in the shapes of PREREGISTRATION.md section 2
- `{"ok":false,"class":C,"status":S|null,"native":"TypeName","msg":"...","ms":N}`, `C` one of
  `auth not_found http network timeout decode validation other`, derived from the SDK's native error type
- `{"na":true}` the SDK has no such operation; `{"inexpressible":true}` the language cannot express the argument
- `{"driver_error":"..."}` harness failure, never a finding

Environment: `SDKDIFF_SDKS_DIR` (checkout of keyorix-sdks), `SDKDIFF_PLANT` (planted defect id; default empty).
