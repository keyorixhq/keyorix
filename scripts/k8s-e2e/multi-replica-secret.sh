#!/usr/bin/env bash
# scripts/k8s-e2e/multi-replica-secret.sh -- two server replicas in the Helm
# chart's Secret mode in a real kind cluster (HA-SECRET-KEYS-1,
# docs/multi-replica-keys.md "Secret mode").
#
# MANUAL target (needs Docker + kind; run it on the e2e VM).
#
# Flow:
#   0. Preflight; build the server binary (admin key-secret / rotate / verify-audit
#      run from here, as an operator would) and the CLI.
#   1. kind cluster (one node); server + web images built from this checkout.
#   2. First install: the auth Secret from 0600 files (--from-file, never on argv),
#      the key Secret from `admin encryption key-secret generate` (immutable), then
#      helm install with server.replicas=2 in Secret mode. Expected: both Ready, no
#      keys PVC, key_dir_lock: database, the key directory read-only in the pod, and
#      the database's dek.epoch equal to the Secret's keyorix.io/dek-fingerprint.
#   3. Bootstrap admin + MFA; a secret written through pod 1 reads back through pod 2.
#   4. DEK rotation in Secret mode: unpack the live Secret into a workspace, scale
#      to 0, `admin encryption rotate --confirm` in the workspace against the
#      release's PostgreSQL (port-forward), `key-secret export` as a NEW Secret.
#      A pod started on the OLD Secret must be refused (DEK epoch); helm upgrade
#      to the new Secret brings both replicas back and the secret still reads.
#   5. Rolling restart: both Ready, the secret still reads.
#   6. Scale to 0; `admin audit export-checkpoint-key` + `admin verify-audit`
#      against the release's database: VALID.
#   7. Cleanup: namespace, work dir (it holds key material), the cluster unless
#      KEYORIX_KMRS_KEEP_CLUSTER=1.
#
# Key material (manifests, workspace) stays in a 0700 work dir and is never
# printed: only fingerprints, file names and counts.
# Names carry the session tag (cluster ha-secret-keys-1-kmrs, namespace kmrs) so
# the script never touches another session's resources on a shared VM.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CLUSTER_NAME="${KEYORIX_KMRS_CLUSTER:-ha-secret-keys-1-kmrs}"
KEEP_CLUSTER="${KEYORIX_KMRS_KEEP_CLUSTER:-0}"
IMAGE_TAG="${KEYORIX_KMRS_IMAGE_TAG:-kmrs}"
NS="kmrs"
REL="kmrs"
DEPLOY="${REL}-keyorix-server"
WORK_DIR="$(mktemp -d)"
chmod 700 "$WORK_DIR"
PORT_FORWARD_PIDS=()

fail() { echo "" >&2; echo "MULTI-REPLICA SECRET-MODE E2E FAILED: $1" >&2; exit 1; }
log() { echo "==> $1"; }

cleanup() {
    log "Cleaning up"
    for pid in "${PORT_FORWARD_PIDS[@]:-}"; do
        [ -n "$pid" ] && kill "$pid" >/dev/null 2>&1 || true
    done
    kubectl delete namespace "$NS" --wait=true --ignore-not-found >/dev/null 2>&1 || true
    rm -rf "$WORK_DIR"
    if [ "$KEEP_CLUSTER" != "1" ]; then
        kind delete cluster --name "$CLUSTER_NAME" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

# --- 0. preflight ---
for bin in docker kind helm kubectl go; do
    command -v "$bin" >/dev/null 2>&1 || fail "$bin is required and not on PATH"
done
docker info >/dev/null 2>&1 || fail "Docker daemon not reachable"

log "Building the server binary and the CLI"
SERVER_BIN="$WORK_DIR/keyorix-server"
(cd "$REPO_ROOT" && go build -o "$SERVER_BIN" ./server)
CLI_BIN="$WORK_DIR/keyorix"
(cd "$REPO_ROOT/cli" && GOWORK=off go build -o "$CLI_BIN" .)
CLI_HOME="$WORK_DIR/cli-home"
mkdir -p "$CLI_HOME"
kx() { HOME="$CLI_HOME" KEYORIX_CA_FILE="$WORK_DIR/server-ca.pem" "$CLI_BIN" "$@"; }
totp() { (cd "$REPO_ROOT" && GOWORK=off go run scripts/totpgen/main.go "$@"); }

# Credentials as 0600 files only: they reach Kubernetes through --from-file.
ADMIN_PASSWORD='Kmrs-Replicas-Passw0rd!'
(
    umask 077
    printf '%s' 'kmrs-master-password-0123456789' >"$WORK_DIR/master-password"
    printf '%s' 'kmrs-db-password' >"$WORK_DIR/db-password"
    printf '%s' "$ADMIN_PASSWORD" >"$WORK_DIR/admin-password"
    head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n' >"$WORK_DIR/bootstrap-token"
)

# --- 1. cluster, images ---
if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
    log "Creating kind cluster $CLUSTER_NAME"
    kind create cluster --name "$CLUSTER_NAME" --wait 120s
fi
kubectl config use-context "kind-${CLUSTER_NAME}" >/dev/null
log "Building images (:$IMAGE_TAG)"
docker build -q -t "keyorix-server:${IMAGE_TAG}" -f "$REPO_ROOT/server/Dockerfile" "$REPO_ROOT" >/dev/null
docker build -q -t "keyorix-web:${IMAGE_TAG}" -f "$REPO_ROOT/web/Dockerfile" "$REPO_ROOT/web" >/dev/null
kind load docker-image "keyorix-server:${IMAGE_TAG}" "keyorix-web:${IMAGE_TAG}" --name "$CLUSTER_NAME" >/dev/null

server_pods() {
    kubectl -n "$NS" get pods -l app.kubernetes.io/component=server --field-selector=status.phase!=Failed \
        -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}'
}
ready_count() {
    kubectl -n "$NS" get pods -l app.kubernetes.io/component=server \
        -o jsonpath='{range .items[*]}{.status.containerStatuses[0].ready}{"\n"}{end}' | grep -c '^true$' || true
}
port_forward() {
    # port_forward <target> <local>:<remote>; registers the PID for cleanup.
    kubectl -n "$NS" port-forward "$1" "$2" >/dev/null 2>&1 &
    PORT_FORWARD_PIDS+=("$!")
    for _ in $(seq 1 30); do
        (exec 3<>"/dev/tcp/127.0.0.1/${2%%:*}") 2>/dev/null && exec 3>&- && return 0
        sleep 1
    done
    fail "port-forward $1 never became reachable"
}
stop_port_forwards() {
    for pid in "${PORT_FORWARD_PIDS[@]:-}"; do
        [ -n "$pid" ] && kill "$pid" >/dev/null 2>&1 || true
    done
    PORT_FORWARD_PIDS=()
}
annotation_fp() { # annotation_fp <manifest file>
    sed -n 's/^    keyorix.io\/dek-fingerprint: "\([0-9a-f]*\)"$/\1/p' "$1"
}
db_epoch() {
    kubectl -n "$NS" exec "${REL}-keyorix-postgresql-0" -- \
        psql -U keyorix -d keyorix -tAc "SELECT value FROM system_metadata WHERE key = 'dek.epoch'" 2>/dev/null | tr -d '[:space:]'
}
scale_to_zero() {
    kubectl -n "$NS" scale "deploy/$DEPLOY" --replicas=0 >/dev/null
    kubectl -n "$NS" wait --for=delete pod -l app.kubernetes.io/component=server --timeout 180s >/dev/null 2>&1 || true
    [ -z "$(server_pods)" ] || fail "server pods still present after scaling to 0"
}

# --- 2. first install ---
log "First install: auth Secret, key Secret (key-secret generate), helm install (2 replicas, Secret mode)"
kubectl delete namespace "$NS" --wait=true --ignore-not-found >/dev/null 2>&1 || true
kubectl create namespace "$NS" >/dev/null
kubectl -n "$NS" create secret generic kmrs-auth \
    --from-file=KEYORIX_MASTER_PASSWORD="$WORK_DIR/master-password" \
    --from-file=KEYORIX_DB_PASSWORD="$WORK_DIR/db-password" \
    --from-file=KEYORIX_ADMIN_PASSWORD="$WORK_DIR/admin-password" \
    --from-file=KEYORIX_BOOTSTRAP_TOKEN="$WORK_DIR/bootstrap-token" >/dev/null

KEYGEN_CFG="$WORK_DIR/keygen.yaml"
(umask 077 && printf 'storage:\n  encryption:\n    enabled: true\n    dek_path: /app/keys/data.key\n    salt_path: /app/keys/kek.salt\n' >"$KEYGEN_CFG")
"$SERVER_BIN" admin encryption key-secret generate --config "$KEYGEN_CFG" \
    --passphrase-file "$WORK_DIR/master-password" \
    --name kmrs-keys-1 --namespace "$NS" --out "$WORK_DIR/keys-1.yaml" >/dev/null 2>"$WORK_DIR/generate.log" \
    || { grep -v 'data.key:\|kek.salt:' "$WORK_DIR/generate.log" >&2; fail "key-secret generate failed"; }
FP1="$(annotation_fp "$WORK_DIR/keys-1.yaml")"
[ -n "$FP1" ] || fail "keys-1.yaml has no keyorix.io/dek-fingerprint annotation"
kubectl create -f "$WORK_DIR/keys-1.yaml" >/dev/null || fail "kubectl create of the key Secret failed"
[ "$(kubectl -n "$NS" get secret kmrs-keys-1 -o jsonpath='{.immutable}')" = "true" ] || fail "the key Secret is not immutable"

HA_SETS=(
    --set server.replicas=2
    --set server.keysSecret.enabled=true
    --set server.keysPersistence.enabled=false
    --set auth.existingSecret=kmrs-auth
    --set auth.existingSecretKeys.adminPassword=true
    --set auth.existingSecretKeys.bootstrapToken=true
    --set server.image.repository=keyorix-server --set server.image.tag="$IMAGE_TAG"
    --set web.image.repository=keyorix-web --set web.image.tag="$IMAGE_TAG"
)
helm install "$REL" "$REPO_ROOT/deploy/helm/keyorix" -n "$NS" "${HA_SETS[@]}" \
    --set server.keysSecret.name=kmrs-keys-1 --wait --timeout 300s >/dev/null \
    || fail "helm install --wait (Secret mode, 2 replicas) failed"
[ "$(ready_count)" = "2" ] || fail "expected 2 Ready replicas, got $(ready_count)"
kubectl -n "$NS" get pvc -o name | grep -q 'server-keys' && fail "Secret mode created a keys PVC"
kubectl -n "$NS" get configmap "${DEPLOY}-config" -o jsonpath='{.data.keyorix\.yaml}' | grep -q 'key_dir_lock: database' \
    || fail "the server config lacks key_dir_lock: database"
read -r POD1 POD2 <<<"$(server_pods | tr '\n' ' ')"
if kubectl -n "$NS" exec "$POD1" -c server -- sh -c 'touch /app/keys/probe' >/dev/null 2>&1; then
    fail "the server's key directory is writable"
fi
[ "$(db_epoch)" = "$FP1" ] || fail "the database's dek.epoch is not the key Secret's fingerprint"
log "Both replicas Ready ($POD1, $POD2) on kmrs-keys-1 (DEK fingerprint $FP1), keys read-only"

# --- 3. cross-replica write/read ---
kubectl -n "$NS" get secret "${REL}-keyorix-secure-baseline" -o jsonpath='{.data.server\.crt}' | base64 -d >"$WORK_DIR/server-ca.pem"
login() { # login <port>
    KEYORIX_PASSWORD="$ADMIN_PASSWORD" KEYORIX_MFA_CODE="$(totp "$MFA_SECRET" 30)" \
        kx login --server "https://localhost:$1" --username admin >/dev/null || fail "login on :$1 failed"
}
read_value() { kx secret get --id 1 --show-value | awk '/^Decrypted Value/{getline; getline; print}'; }
port_forward "pod/$POD1" 18291:8080
port_forward "pod/$POD2" 18292:8080
KEYORIX_PASSWORD="$ADMIN_PASSWORD" kx login --server https://localhost:18291 --username admin >/dev/null || fail "login (pod 1) failed"
ENROLL_OUT="$(kx mfa enroll)" || fail "mfa enroll failed"
MFA_SECRET="$(echo "$ENROLL_OUT" | grep -E '^  [A-Z2-7]+$' | tr -d '[:space:]')"
[ -n "$MFA_SECRET" ] || fail "could not parse the MFA secret"
KEYORIX_MFA_CODE="$(totp "$MFA_SECRET")" KEYORIX_PASSWORD="$ADMIN_PASSWORD" kx mfa activate >/dev/null || fail "mfa activate failed"
login 18291
(cd "$CLI_HOME" && umask 077 && printf '%s' 'kmrs-cross-replica-value' >./v.txt \
    && kx secret create --name kmrs-cross-replica --from-file ./v.txt --project 1 --environment 1 >/dev/null) \
    || fail "secret create through pod 1 failed"
login 18292
[ "$(read_value)" = "kmrs-cross-replica-value" ] || fail "pod 2 cannot read what pod 1 wrote"
log "Written through $POD1, read back through $POD2"
stop_port_forwards

# --- 4. DEK rotation in Secret mode ---
log "Rotation: unpack the live Secret into a workspace, scale to 0, rotate, export a new Secret"
(umask 077 && kubectl -n "$NS" get secret kmrs-keys-1 -o yaml >"$WORK_DIR/current.yaml")
WS="$WORK_DIR/ws"
"$SERVER_BIN" admin encryption key-secret unpack --in "$WORK_DIR/current.yaml" --dir "$WS" >/dev/null 2>&1 \
    || fail "key-secret unpack failed"
scale_to_zero
port_forward "svc/${REL}-keyorix-postgresql" 15432:5432
(umask 077 && cat >"$WS/keyorix.yaml" <<EOF
environment: production
storage:
  type: postgres
  database:
    host: 127.0.0.1
    port: "15432"
    name: keyorix
    user: keyorix
    ssl_mode: require
  encryption:
    enabled: true
    dek_path: data.key
    salt_path: kek.salt
    key_dir_lock: database
EOF
)
admin() { (cd "$WS" && KEYORIX_DB_PASSWORD_FILE="$WORK_DIR/db-password" "$SERVER_BIN" admin "$@" --config keyorix.yaml); }
admin encryption rotate --confirm --passphrase-file "$WORK_DIR/master-password" >"$WORK_DIR/rotate.log" 2>&1 \
    || { tail -5 "$WORK_DIR/rotate.log" >&2; fail "admin encryption rotate in the workspace failed"; }
admin encryption key-secret export --passphrase-file "$WORK_DIR/master-password" \
    --name kmrs-keys-2 --namespace "$NS" --out "$WORK_DIR/keys-2.yaml" >/dev/null 2>&1 \
    || fail "key-secret export after the rotation failed"
FP2="$(annotation_fp "$WORK_DIR/keys-2.yaml")"
[ -n "$FP2" ] && [ "$FP2" != "$FP1" ] || fail "the rotation did not produce a new DEK fingerprint"
[ "$(db_epoch)" = "$FP2" ] || fail "the database's dek.epoch is not the new Secret's fingerprint"
kubectl create -f "$WORK_DIR/keys-2.yaml" >/dev/null || fail "kubectl create of the new key Secret failed"
stop_port_forwards
log "Rotated: DEK fingerprint $FP1 -> $FP2, new Secret kmrs-keys-2"

log "A pod started on the OLD key Secret must be refused (DEK epoch)"
kubectl -n "$NS" scale "deploy/$DEPLOY" --replicas=1 >/dev/null
REFUSED=""
for _ in $(seq 1 36); do
    for p in $(server_pods); do
        if kubectl -n "$NS" logs "$p" -c server --previous 2>/dev/null | grep -q "DEK is not the DEK the database is encrypted under" \
            || kubectl -n "$NS" logs "$p" -c server 2>/dev/null | grep -q "DEK is not the DEK the database is encrypted under"; then
            REFUSED="$p"
        fi
    done
    [ -n "$REFUSED" ] && break
    sleep 5
done
[ -n "$REFUSED" ] || fail "a server on the old key Secret was not refused"
[ "$(ready_count)" = "0" ] || fail "a server on the old key Secret became Ready"
log "Refused as expected: $REFUSED"

helm upgrade "$REL" "$REPO_ROOT/deploy/helm/keyorix" -n "$NS" --reuse-values \
    --set server.keysSecret.name=kmrs-keys-2 --set server.replicas=2 --wait --timeout 300s >/dev/null \
    || fail "helm upgrade to the new key Secret failed"
[ "$(ready_count)" = "2" ] || fail "after the upgrade: expected 2 Ready replicas, got $(ready_count)"
read -r POD1 POD2 <<<"$(server_pods | tr '\n' ' ')"
port_forward "pod/$POD1" 18293:8080
port_forward "pod/$POD2" 18294:8080
login 18293
[ "$(read_value)" = "kmrs-cross-replica-value" ] || fail "the secret does not read after the rotation (pod 1)"
login 18294
[ "$(read_value)" = "kmrs-cross-replica-value" ] || fail "the secret does not read after the rotation (pod 2)"
stop_port_forwards
log "Both replicas on kmrs-keys-2 read the secret"

# --- 5. rolling restart ---
log "Rolling restart"
kubectl -n "$NS" rollout restart "deploy/$DEPLOY" >/dev/null
kubectl -n "$NS" rollout status "deploy/$DEPLOY" --timeout 300s >/dev/null || fail "rolling restart did not complete"
[ "$(ready_count)" = "2" ] || fail "after the rolling restart: expected 2 Ready replicas, got $(ready_count)"
read -r POD1 _ <<<"$(server_pods | tr '\n' ' ')"
port_forward "pod/$POD1" 18295:8080
login 18295
[ "$(read_value)" = "kmrs-cross-replica-value" ] || fail "the secret does not read after the rolling restart"
stop_port_forwards

# --- 6. verify-audit ---
log "verify-audit against the release's database (replicas stopped)"
scale_to_zero
port_forward "svc/${REL}-keyorix-postgresql" 15432:5432
admin audit export-checkpoint-key --passphrase-file "$WORK_DIR/master-password" --output "$WORK_DIR/checkpoint.key" >/dev/null 2>&1 \
    || fail "admin audit export-checkpoint-key failed"
set +e
admin verify-audit --checkpoint-key-file "$WORK_DIR/checkpoint.key" >"$WORK_DIR/verify-audit.txt" 2>&1
VERIFY_RC=$?
set -e
[ "$VERIFY_RC" = "0" ] || { tail -20 "$WORK_DIR/verify-audit.txt" >&2; fail "verify-audit exit $VERIFY_RC, want 0 (VALID)"; }
stop_port_forwards

log "MULTI-REPLICA SECRET-MODE E2E PASSED"
