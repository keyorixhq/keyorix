# Keyorix Secrets — GitHub Action

Fetch secrets from a [Keyorix](https://github.com/keyorixhq/keyorix) server into
your workflow as **masked environment variables**.

```yaml
- name: Load Keyorix secrets
  uses: keyorixhq/keyorix/integrations/github-action@v1
  with:
    server: ${{ secrets.KEYORIX_SERVER }}
    token: ${{ secrets.KEYORIX_TOKEN }}
    project: payments
    environment: production

- run: ./deploy.sh   # secrets available as env vars, e.g. $STRIPE_KEY
```

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `server` | yes | — | Keyorix server URL |
| `token` | yes | — | API token (machine/PAT) with `secrets.read` |
| `project` | no | `default` | Project name |
| `environment` | no | `development` | Environment name |
| `version` | no | latest | Keyorix CLI version to install (e.g. `v0.2.0`) |
| `export-to-env` | no | `true` | Inject secrets as masked env vars |
| `output-file` | no | — | Also write secrets to this dotenv file |

How it works: installs the Keyorix CLI (via the official installer, or a pinned
`version`), runs `keyorix secret export --format json`, masks each value with
`::add-mask::`, and writes them to `$GITHUB_ENV`. Secret names are injected
verbatim — name them as valid env identifiers (e.g. `STRIPE_KEY`).

See [docs/CI_CD.md](../../docs/CI_CD.md) for GitLab CI and CircleCI examples.
