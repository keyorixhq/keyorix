# Deploying on Kubernetes

Installing the Helm chart with defaults, checking it's healthy, and upgrading. Every step
below was run for real against a fresh `kind` cluster while writing this page.

> **Known gap (tracked, not yet fixed):** as of this writing, a default install of this
> chart crash-loops the server pod every time — see the callout after step 2. This page
> documents the real commands and the real failure so you don't waste time assuming your
> own cluster or values are wrong. See `reports/UX.md` ("J8" section) and
> `FINDINGS-inbox.md` for the root cause and the fix.

## 1. Install with defaults

```bash
helm install keyorix ./deploy/helm/keyorix \
  --set auth.masterPassword='change-me-and-keep-it' \
  --set postgresql.auth.password='a-strong-db-password' \
  --set auth.adminPassword='Admin123!'
```

Expected — the chart installs and prints clear next steps:

```
NOTES:
Keyorix has been deployed as release "keyorix".
1. Wait for the pods to be ready:
   kubectl -n default get pods -l app.kubernetes.io/instance=keyorix -w
2. Reach the UI:
   kubectl -n default port-forward svc/keyorix-keyorix-web 8080:80
   open http://localhost:8080
3. Log in with the admin you configured (auth.adminUsername="admin").
⚠️  CRITICAL — back up the encryption keys volume
    ...
```

## 2. Check pod health

```bash
kubectl get pods -l app.kubernetes.io/instance=keyorix -w
```

`postgresql` and `web` come up `1/1 Running` within a few seconds. **`server` currently
does not** — it crash-loops:

```
NAME                             READY   STATUS             RESTARTS
keyorix-keyorix-server-...       0/1     CrashLoopBackOff   1
```

```bash
kubectl logs <server-pod-name> --previous
```

```
failed to initialize core service: failed to initialize encryption: failed to initialize
encryption (KEK derivation): failed to initialize key manager: failed to write salt:
access denied: path "/app/keys/kek.salt" must be relative
```

This is a real defect in the chart (its config template hardcodes an absolute path for
the encryption key files; the server's path-safety check rejects any absolute path) — not
something wrong with your cluster, your values, or your image. It affects every install of
this chart, every time, with no values-based workaround available today (the key paths
aren't exposed as a chart value). Track the fix status in the report/findings files
referenced above before spending time debugging your own setup further.

## 3. Once the server pod is healthy: reach the UI

```bash
kubectl port-forward svc/keyorix-keyorix-web 8080:80
open http://localhost:8080
```

Log in with the admin credentials you set in step 1.

## 4. Upgrade

`helm upgrade` itself works correctly independent of the issue above — verified by
re-running the same install command as `helm upgrade` with no chart-level error:

```bash
helm upgrade keyorix ./deploy/helm/keyorix \
  --set auth.masterPassword='change-me-and-keep-it' \
  --set postgresql.auth.password='a-strong-db-password' \
  --set auth.adminPassword='Admin123!' \
  --set web.replicaCount=2
```

```
Release "keyorix" has been upgraded. Happy Helming!
```

Read `deploy/helm/keyorix/README.md`'s "Upgrading: egress NetworkPolicy" section before
your first upgrade of an existing install — it changes default pod-to-pod network access.
