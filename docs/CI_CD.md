# Using Keyorix secrets in CI/CD

Fetch secrets from a Keyorix server into a pipeline at build/deploy time, instead
of duplicating them into each CI system. All three examples below authenticate
with a **Keyorix API token** (a machine token or personal access token that has
`secrets.read`), stored as a CI secret — never commit it.

Set two values as CI secrets/variables in every system:

| Variable | Value |
|----------|-------|
| `KEYORIX_SERVER` | Your server URL, e.g. `https://keyorix.your-company.internal` |
| `KEYORIX_TOKEN` | A machine/PAT token with `secrets.read` on the target project |

## GitHub Actions

Use the bundled action. It installs the Keyorix CLI, fetches the chosen
project/environment, and injects each secret as a **masked** environment
variable for the following steps.

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Load Keyorix secrets
        uses: keyorixhq/keyorix/integrations/github-action@v1
        with:
          server: ${{ secrets.KEYORIX_SERVER }}
          token: ${{ secrets.KEYORIX_TOKEN }}
          project: payments
          environment: production
          # version: v0.2.0      # pin the CLI (default: latest release)
          # export-to-env: true  # inject as env vars (default)
          # output-file: .env    # also write a dotenv file

      - name: Deploy
        run: ./deploy.sh   # secrets are now in the environment, e.g. $STRIPE_KEY
```

**Inputs:** `server`, `token` (required); `project` (default `default`),
`environment` (default `development`), `version` (default latest),
`export-to-env` (default `true`), `output-file` (default none).

Values are masked with `::add-mask::` so they won't print in logs. Secret names
are injected verbatim, so name your secrets as valid environment identifiers
(e.g. `STRIPE_KEY`) for the smoothest consumption.

## GitLab CI

GitLab has no Keyorix action, so install the CLI and export directly. Store
`KEYORIX_SERVER` / `KEYORIX_TOKEN` as **masked** CI/CD variables.

```yaml
deploy:
  image: debian:stable-slim
  before_script:
    - apt-get update -qq && apt-get install -y -qq curl ca-certificates
    - curl -fsSL https://raw.githubusercontent.com/keyorixhq/keyorix/main/install.sh | sh
  script:
    # Export to a dotenv file, then load it into the environment.
    - keyorix secret export --project payments --env production --format dotenv > keyorix.env
    - set -a && . ./keyorix.env && set +a
    - ./deploy.sh
  after_script:
    - rm -f keyorix.env
```

> Note: GitLab only auto-masks variables you declare as masked. Values fetched
> at runtime are not masked — don't `echo` them.

## CircleCI

Set `KEYORIX_SERVER` / `KEYORIX_TOKEN` as project environment variables (or a
context). Install the CLI and export within the job.

```yaml
version: 2.1
jobs:
  deploy:
    docker:
      - image: cimg/base:current
    steps:
      - checkout
      - run:
          name: Load Keyorix secrets
          command: |
            curl -fsSL https://raw.githubusercontent.com/keyorixhq/keyorix/main/install.sh | sh
            keyorix secret export --project payments --env production --format dotenv > keyorix.env
            set -a && . ./keyorix.env && set +a
            ./deploy.sh
workflows:
  deploy:
    jobs:
      - deploy
```

## Token scope

Issue a dedicated **machine identity** token (ADR-030) scoped to just the
project/environment the pipeline needs, with `secrets.read` only — not an admin
token. Rotate it like any other CI credential.
