## BREAKING: a `*` in a CORS origin refuses to start (#4382)

`server.http.allowed_origins` entries such as `https://*` or `https://*.example.com`
were accepted and treated by the CORS layer as patterns, giving every matching
origin a credentialed response. The same applied to `server.http.domain` when
`allowed_origins` is empty (the default origin is `https://<domain>`). Both now
refuse to start, naming the setting. Before upgrading, check your config:

```sh
grep -nE 'allowed_origins|domain:' /etc/keyorix/keyorix.yaml
```

and replace any pattern with the exact origins your web UI is served from, e.g.
`allowed_origins: ["https://keyorix.example.com"]`.
