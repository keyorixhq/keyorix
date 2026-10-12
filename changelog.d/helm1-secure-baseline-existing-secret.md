### Deployment
- **Helm: `secureBaseline.existingSecret`** for ArgoCD and other GitOps tools that
  render with `helm template`. There `lookup` sees no cluster, so the generated
  certificates and `/metrics` token changed on every sync. With the value set to a
  pre-created Secret (keys `server.crt`, `server.key`, `metrics_token`, and
  `postgres.crt`, `postgres.key` for the bundled Postgres) the chart generates
  nothing, renders no `-secure-baseline` Secret and mounts yours; two renders are
  byte-identical. A missing key fails `helm install/upgrade` with its name, and
  setting it without `secureBaseline.enabled=true` fails the render. Unset, the
  render is unchanged. See `deploy/helm/keyorix/README.md`.
