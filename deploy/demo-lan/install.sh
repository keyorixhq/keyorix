#!/usr/bin/env bash
# deploy/demo-lan/install.sh — a Keyorix demo (or pilot) box on a LAN or an air-gapped network
# with working HTTPS from ONE command: no ACME, no public DNS, no manual openssl.
#
#   sudo deploy/demo-lan/install.sh --bin-dir /path/to/linux-binaries [--dir /opt/keyorix-demo]
#                                   [--port 8080] [--hostname NAME] [--ip ADDR] [--reuse] [--new-ca]
#
#   --bin-dir D   directory with the LINUX binaries keyorix, keyorix-server and totpgen (required)
#   --dir D       where everything lives (default /opt/keyorix-demo): bin/, scripts/, pki/, state/
#   --port N      HTTPS port (default 8080)
#   --hostname H  an extra DNS name for the certificate (default: this box's own hostname)
#   --ip ADDR     use this address instead of the detected one (a multi-homed box)
#   --reuse       keep an existing install in --dir (config, data, secrets): only refresh the
#                 binaries, the certificate, the unit and re-run the (idempotent) seed and check
#   --new-ca      the box got a new address or name: replace the local CA (the old one is kept);
#                 every client then trusts the new CA once
#
# What it does, in order (each step says what it does; nothing is deleted, whatever it replaces
# is copied to --dir/backup-<utc time>/ first):
#   1. creates a LOCAL CA once (ECDSA P-256, 10 years, key 0600, X.509 nameConstraints limited to
#      this box's address and names) and signs the server certificate with it (deploy/demo-lan/pki.sh);
#      the certificate is re-issued automatically when fewer than 30 days are left (before every
#      start, and by a daily timer), so clients trust the CA ONCE and renewals need nothing;
#   2. initialises a fresh server (scripts/demo/native-up.sh's demo settings: break-glass, 15 s
#      anomaly detector, oidc, dynamic secrets) listening on 0.0.0.0 with TLS on, with a random
#      master password and bootstrap token in a 0600 EnvironmentFile (never on argv or stdout);
#   3. installs and enables a systemd unit (Restart=always) plus the renewal timer;
#   4. seeds the demo org (scripts/demo/seed-demo.sh) and runs scripts/demo/check.sh --used;
#   5. prints the URL, the CA file, its SHA-256 fingerprint and the commands to trust it.
# Trusting the CA in each browser/OS is the only manual step.
#
# Needs: root, systemd, openssl, python3, curl, and a keyorix checkout or release tarball that has
# scripts/demo and deploy/demo-lan (this script's own location). Refuses to run over an existing
# keyorix.db in --dir unless --reuse is given. The demo logins are the repository's public demo
# passwords with MFA on: this is a demo box, keep it off untrusted networks.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# What the seed and check scripts need next to bin/ (they find their own repo root two levels up:
# check.sh --used runs the golden-path break-glass section, which reads docs/demo/GOLDEN-PATH.md).
KIT_FILES=(
  scripts/demo/lib.sh scripts/demo/seed.sh scripts/demo/seed-demo.sh scripts/demo/check.sh
  scripts/demo/golden-path-breakglass.sh scripts/demo/golden-path-s7.sh scripts/demo/latency-baseline.txt
  docs/demo/GOLDEN-PATH.md
)

say() { echo "==> $*"; }
info() { echo "    $*"; }
warn() { echo "WARNING: $*" >&2; }
die()  { echo "ERROR: $*" >&2; exit 1; }

# detect_ip prints this box's primary IPv4 address: the source address of the route to a
# documentation-range address (nothing is sent), else the first address of `hostname -I`.
detect_ip() {
  local ip=""
  if command -v ip >/dev/null 2>&1; then
    # `ip route get` fails when there is no route (an air-gapped box): that is not an error here.
    ip="$(ip -4 route get 192.0.2.1 2>/dev/null | sed -n 's/.* src \([0-9][0-9.]*\).*/\1/p' | head -1 || true)"
  fi
  if [ -z "$ip" ] && command -v hostname >/dev/null 2>&1; then
    ip="$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+(\.[0-9]+){3}$' | grep -vE '^(127\.|169\.254\.)' | head -1 || true)"
  fi
  printf '%s' "$ip"
}

# port_busy PORT: something already listens on it.
port_busy() {
  if command -v ss >/dev/null 2>&1; then
    ss -ltn "sport = :$1" 2>/dev/null | tail -n +2 | grep -q .
  else
    ( exec 3<>"/dev/tcp/127.0.0.1/$1" ) 2>/dev/null
  fi
}

# is_elf FILE: starts with the ELF magic (a Linux binary, not a macOS one).
is_elf() { [ "$(head -c 4 "$1" 2>/dev/null | od -An -tx1 | tr -d ' \n')" = "7f454c46" ]; }

usage() { grep '^#' "${BASH_SOURCE[0]}" | sed 's/^# \?//' | sed -n '2,36p'; }

main() {
  local BIN_DIR="" DIR="/opt/keyorix-demo" PORT="8080" HOSTNAME_ARG="" IP_ARG="" REUSE=false NEW_CA=false
  while [ $# -gt 0 ]; do
    case "$1" in
      --bin-dir)  [ $# -ge 2 ] || die "--bin-dir needs a value"; BIN_DIR="$2"; shift 2 ;;
      --dir)      [ $# -ge 2 ] || die "--dir needs a value"; DIR="$2"; shift 2 ;;
      --port)     [ $# -ge 2 ] || die "--port needs a value"; PORT="$2"; shift 2 ;;
      --hostname) [ $# -ge 2 ] || die "--hostname needs a value"; HOSTNAME_ARG="$2"; shift 2 ;;
      --ip)       [ $# -ge 2 ] || die "--ip needs a value"; IP_ARG="$2"; shift 2 ;;
      --reuse)    REUSE=true; shift ;;
      --new-ca)   NEW_CA=true; shift ;;
      -h|--help)  usage; exit 0 ;;
      *)          die "unknown argument: $1 (see --help)" ;;
    esac
  done

  # ── 0. Check everything we can before touching anything ───────────────────
  [ -n "$BIN_DIR" ] || die "--bin-dir is required: the directory holding the Linux binaries keyorix, keyorix-server and totpgen"
  [[ "$DIR" =~ ^/[A-Za-z0-9._/-]+$ ]] || die "--dir must be an absolute path of letters, digits and . _ / - only (it goes into a systemd unit): $DIR"
  [[ "$PORT" =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] || die "--port must be 1-65535: $PORT"
  [ -d "$BIN_DIR" ] || die "--bin-dir is not a directory: $BIN_DIR"
  local b
  for b in keyorix keyorix-server totpgen; do
    [ -f "$BIN_DIR/$b" ] || die "missing binary: $BIN_DIR/$b (needed: keyorix, keyorix-server, totpgen; build with GOOS=linux, see docs/demo/LAN-TLS.md)"
    is_elf "$BIN_DIR/$b" || die "$BIN_DIR/$b is not a Linux (ELF) binary: this box needs linux builds (GOOS=linux GOARCH=<this box's arch>)"
  done
  local s
  for s in "${KIT_FILES[@]}"; do
    [ -f "$REPO_ROOT/$s" ] || die "$REPO_ROOT/$s not found: run install.sh from a keyorix checkout or release tarball (it needs scripts/demo, docs/demo and deploy/demo-lan)"
  done
  [ -f "$SCRIPT_DIR/pki.sh" ] || die "$SCRIPT_DIR/pki.sh not found: install.sh and pki.sh must stay together"
  local STATE="$DIR/state" PKI="$DIR/pki" ENVF="$DIR/env"
  local CA_DIR="$PKI/ca" LEAF_DIR="$PKI/leaf" CA_PUB="$DIR/keyorix-demo-ca.crt"
  local UNIT; UNIT="keyorix-lan-$(basename "$DIR")"
  local UNIT_FILE="/etc/systemd/system/$UNIT.service"
  local MARKER="# keyorix demo-lan install.sh dir=$DIR"
  local STAGE="$STATE/.install-stage"

  # Existing install: refuse unless --reuse (the data and the master password belong together).
  if [ -e "$STATE/keyorix.db" ] && [ "$REUSE" != true ]; then
    die "$STATE/keyorix.db already exists: refusing to touch an existing install.
       Re-run with --reuse to keep it (refreshes binaries, certificate and unit), or pick another --dir.
       Nothing was changed."
  fi
  if [ "$REUSE" = true ] && [ -e "$STATE/keyorix.db" ]; then
    [ -s "$STATE/keyorix.yaml" ] && [ -s "$ENVF" ] && [ "$(cat "$STAGE" 2>/dev/null)" = "init-done" ] \
      || die "--reuse: $DIR holds a database but not a finished install (config, $ENVF or $STAGE missing).
       Move $DIR aside (nothing here is deleted by this script) and install again."
    local have_port; have_port="$(sed -n 's/^    port: "\([0-9][0-9]*\)".*/\1/p' "$STATE/keyorix.yaml" | head -1)"
    [ -z "$have_port" ] || [ "$have_port" = "$PORT" ] || die "--reuse: the existing config listens on port $have_port, not $PORT; re-run with --port $have_port"
  fi
  # The checks above only read; from here on the box itself is examined.
  if [ ! -d /run/systemd/system ] || ! command -v systemctl >/dev/null 2>&1; then
    die "this box does not run systemd (no /run/systemd/system): this installer needs it; see docs/demo/LAN-TLS.md for the manual steps"
  fi
  [ "$(id -u)" -eq 0 ] || die "must be run as root (it writes /etc/systemd/system and listens on the LAN): sudo $0 ..."
  local tool
  for tool in openssl python3 curl; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is required and not installed (apt install $tool / dnf install $tool)"
  done
  # A unit of that name that this script did not write is somebody else's: never overwrite it.
  if [ -e "$UNIT_FILE" ] && ! grep -qxF "$MARKER" "$UNIT_FILE"; then
    die "$UNIT_FILE exists and was not written by this installer for $DIR: refusing to overwrite it (pick another --dir)"
  fi
  local unit_active=false
  systemctl is-active --quiet "$UNIT" 2>/dev/null && unit_active=true
  if [ "$unit_active" != true ] && port_busy "$PORT"; then
    die "port $PORT is already in use on this box: pick another with --port (see: ss -ltnp 'sport = :$PORT')"
  fi

  local IP="$IP_ARG"
  [ -n "$IP" ] || IP="$(detect_ip)"
  [ -n "$IP" ] || die "could not detect this box's IPv4 address (no route, no hostname -I): pass --ip ADDR"
  [[ "$IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "not an IPv4 address: $IP"
  local short_host fqdn
  short_host="$(hostname -s 2>/dev/null || hostname)"; fqdn="$(hostname -f 2>/dev/null || true)"
  local PKI_NAMES=(--ip "$IP")
  local n
  if [ -n "$HOSTNAME_ARG" ]; then
    [[ "$HOSTNAME_ARG" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || die "--hostname is not a usable DNS name: $HOSTNAME_ARG"
  fi
  for n in "$HOSTNAME_ARG" "$short_host" "$fqdn"; do
    [ -n "$n" ] || continue
    [ "$n" != "localhost" ] || continue
    if [[ ! "$n" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || [[ "$n" =~ ^[0-9.]+$ ]]; then
      info "skipping the box's name '$n' for the certificate (not a usable DNS name); use --hostname to name it"
      continue
    fi
    PKI_NAMES+=(--dns "$n")
  done
  local URL="https://$IP:$PORT"
  say "installing into $DIR, serving $URL (certificate names: $(printf '%s ' "${PKI_NAMES[@]}"))"

  # ── 1. Stop our own unit, lay out the directory, copy binaries and scripts ─
  local STAMP BACKUP; STAMP="$(date -u +%Y%m%dT%H%M%SZ)"; BACKUP="$DIR/backup-$STAMP"
  backup() { # backup FILE: keep a copy of what is about to be replaced
    [ -e "$1" ] || return 0
    mkdir -p "$BACKUP"; chmod 700 "$BACKUP"
    cp -p "$1" "$BACKUP/$(echo "${1#/}" | tr '/' '_')"
    info "backed up $1 -> $BACKUP/"
  }
  if [ "$unit_active" = true ]; then
    say "stopping $UNIT to replace its files (it is started again below)"
    systemctl stop "$UNIT"
  fi
  mkdir -p "$DIR/bin" "$DIR/scripts/demo" "$PKI" "$STATE"
  chmod 755 "$DIR" "$DIR/bin" "$DIR/scripts" "$DIR/scripts/demo"; chmod 700 "$PKI" "$STATE"
  say "copying the binaries and demo scripts"
  local f
  for f in keyorix keyorix-server totpgen; do
    if [ -e "$DIR/bin/$f" ] && cmp -s "$BIN_DIR/$f" "$DIR/bin/$f"; then info "$f unchanged"; continue; fi
    backup "$DIR/bin/$f"
    install -m 0755 "$BIN_DIR/$f" "$DIR/bin/$f.new" && mv "$DIR/bin/$f.new" "$DIR/bin/$f"
    info "installed $DIR/bin/$f"
  done
  local mode
  for f in "${KIT_FILES[@]}"; do
    if [ -e "$DIR/$f" ] && cmp -s "$REPO_ROOT/$f" "$DIR/$f"; then continue; fi
    backup "$DIR/$f"
    mode=0644; case "$f" in *.sh) mode=0755 ;; esac
    mkdir -p "$(dirname "$DIR/$f")"
    install -m "$mode" "$REPO_ROOT/$f" "$DIR/$f"
  done
  if ! { [ -e "$PKI/pki.sh" ] && cmp -s "$SCRIPT_DIR/pki.sh" "$PKI/pki.sh"; }; then
    backup "$PKI/pki.sh"
    install -m 0755 "$SCRIPT_DIR/pki.sh" "$PKI/pki.sh"
  fi

  # ── 2. Local CA + server certificate ──────────────────────────────────────
  say "local CA and server certificate"
  local pki_args=(init --ca-dir "$CA_DIR" --leaf-dir "$LEAF_DIR" "${PKI_NAMES[@]}")
  [ "$NEW_CA" != true ] || pki_args+=(--new-ca)
  "$PKI/pki.sh" "${pki_args[@]}" || die "could not set up the CA/certificate (see the pki: lines above)"
  if [ ! -e "$CA_PUB" ] || ! cmp -s "$CA_DIR/ca.crt" "$CA_PUB"; then
    backup "$CA_PUB"
    install -m 0644 "$CA_DIR/ca.crt" "$CA_PUB"
  fi
  local FP; FP="$(openssl x509 -in "$CA_PUB" -noout -fingerprint -sha256 | sed 's/^.*=//')"

  # ── 3. Secrets and a fresh server (skipped with --reuse on a finished install) ─
  local LOG="$STATE/install.log"
  run_logged() { # run_logged DESCRIPTION CMD...: output to install.log, shown only on failure
    local what="$1"; shift
    # shellcheck disable=SC1090  # the EnvironmentFile written above
    if ! ( cd "$STATE" && set -a && . "$ENVF" && set +a && "$@" ) >> "$LOG" 2>&1; then
      echo "ERROR: $what failed; last lines of $LOG:" >&2; tail -15 "$LOG" | sed 's/^/    /' >&2
      exit 1
    fi
  }
  if [ -e "$STATE/keyorix.db" ]; then
    say "keeping the existing install (--reuse): config, data and secrets untouched"
  else
    say "generating the master password and bootstrap token (0600, never printed)"
    ( umask 077
      [ -s "$ENVF" ] || printf 'KEYORIX_MASTER_PASSWORD=%s\nKEYORIX_BOOTSTRAP_TOKEN=%s\nKEYORIX_CONFIG_PATH=keyorix.yaml\n' \
        "$(openssl rand -hex 24)" "$(openssl rand -hex 32)" > "$ENVF"
      [ -s "$STATE/bootstrap-token" ] || sed -n 's/^KEYORIX_BOOTSTRAP_TOKEN=//p' "$ENVF" > "$STATE/bootstrap-token"
      [ -s "$STATE/metrics-token" ] || openssl rand -hex 32 > "$STATE/metrics-token"
      : > "$LOG" )
    chmod 600 "$ENVF" "$STATE/bootstrap-token" "$STATE/metrics-token" "$LOG"
    say "initialising the server (config, keys, schema)"
    run_logged "admin init" "$DIR/bin/keyorix-server" admin init --dev --config keyorix.yaml
    KLAN_PORT="$PORT" KLAN_CERT="$LEAF_DIR/server.crt" KLAN_KEY="$LEAF_DIR/server.key" KLAN_METRICS="$STATE/metrics-token" \
      python3 -I - "$STATE/keyorix.yaml" <<'PY' || die "could not edit $STATE/keyorix.yaml (the generated template changed?)"
import os, sys
p = sys.argv[1]
s = open(p).read()

def sub(old, new, what):
    global s
    if s.count(old) < 1:
        sys.exit("expected text not found in the generated config: %s" % what)
    s = s.replace(old, new, 1)

# LAN listener with TLS on the generated certificate paths replaced by the local CA's leaf.
sub('    # host: "127.0.0.1"\n    port: "8080"\n',
    '    host: "0.0.0.0"\n    port: "%s"\n    trusted_proxies: ["127.0.0.1/32"]\n' % os.environ["KLAN_PORT"], "server.http host/port")
sub('      enabled: false  # DEV-ONLY: cleartext\n      cert_file: "certs/server.crt"     # Path to TLS certificate\n      key_file: "certs/server.key"      # Path to TLS key\n',
    '      enabled: true\n      cert_file: "%s"\n      key_file: "%s"\n' % (os.environ["KLAN_CERT"], os.environ["KLAN_KEY"]), "server.http.tls")
# /metrics is reachable from the LAN now: give it a token (the dev template leaves it open).
sub('    # DEV-ONLY: no metrics_token_file -- /metrics is unauthenticated\n',
    '    metrics_token_file: "%s"\n' % os.environ["KLAN_METRICS"], "server.http metrics token")
# The rest is scripts/demo/native-up.sh's demo-only settings.
s += """
break_glass:
  enabled: true
  emergency_role: project_developer
  default_ttl: 4h
  max_ttl: 24h
anomaly_alerts:
  enabled: true
  schedule: 15s
# DEMO-ONLY: trust the local stand-in CI issuer for scripts/demo/scenario-oidc-federation.sh.
oidc:
  enabled: true
  issuers:
    - name: demo-ci-platform
      issuer: http://127.0.0.1:18520
      jwks_uri: http://127.0.0.1:18520/jwks.json
      audiences: ["keyorix-demo"]
# DEMO-ONLY: sweep expired leases every 10 s; a database on this machine may be a target.
dynamic_secrets:
  sweep_enabled: true
  sweep_interval: 10s
  insecure_allow_private_network_dynamic_secret_targets: true
"""
open(p, "w").write(s)
PY
    chmod 600 "$STATE/keyorix.yaml"
    run_logged "admin encryption init" "$DIR/bin/keyorix-server" admin encryption init --config keyorix.yaml
    run_logged "admin migrate" "$DIR/bin/keyorix-server" admin migrate --config keyorix.yaml
    printf 'init-done' > "$STAGE"
    info "initialised (details: $LOG)"
  fi

  # ── 4. systemd units: the server and the certificate renewal timer ────────
  say "installing the systemd unit $UNIT.service and the renewal timer"
  backup "$UNIT_FILE"
  cat > "$UNIT_FILE" <<EOF
$MARKER
[Unit]
Description=Keyorix LAN demo ($DIR)
After=network-online.target
Wants=network-online.target

[Service]
WorkingDirectory=$STATE
EnvironmentFile=$ENVF
ExecStartPre=$PKI/pki.sh renew --ca-dir $CA_DIR --leaf-dir $LEAF_DIR
ExecStart=$DIR/bin/keyorix-server
Restart=always
RestartSec=5
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
StandardOutput=append:$STATE/server.log
StandardError=append:$STATE/server.log

[Install]
WantedBy=multi-user.target
EOF
  backup "/etc/systemd/system/$UNIT-renew.service"
  cat > "/etc/systemd/system/$UNIT-renew.service" <<EOF
$MARKER
[Unit]
Description=Keyorix LAN demo: renew the server certificate when fewer than 30 days are left ($DIR)

[Service]
Type=oneshot
ExecStart=$PKI/pki.sh renew --ca-dir $CA_DIR --leaf-dir $LEAF_DIR --restart-unit $UNIT.service
EOF
  backup "/etc/systemd/system/$UNIT-renew.timer"
  cat > "/etc/systemd/system/$UNIT-renew.timer" <<EOF
$MARKER
[Unit]
Description=Daily certificate renewal check for the Keyorix LAN demo ($DIR)

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable --now "$UNIT.service" >/dev/null 2>&1 || die "could not enable/start $UNIT.service: systemctl status $UNIT.service; journalctl -u $UNIT -n 30 --no-pager"
  systemctl enable --now "$UNIT-renew.timer" >/dev/null 2>&1 || warn "could not enable $UNIT-renew.timer; the certificate is still renewed on every start"
  info "enabled $UNIT.service (Restart=always) and $UNIT-renew.timer"

  say "waiting for the server (https://127.0.0.1:$PORT/health, up to 90 s)"
  local i healthy=false
  for i in $(seq 1 45); do
    if curl -s -o /dev/null --max-time 3 --cacert "$CA_PUB" "https://127.0.0.1:$PORT/health"; then healthy=true; break; fi
    systemctl is-active --quiet "$UNIT" || { warn "$UNIT is not running"; break; }
    [ $((i % 5)) -ne 0 ] || info "still waiting... (${i}x2 s)"
    sleep 2
  done
  if [ "$healthy" != true ]; then
    echo "ERROR: the server did not become healthy; last lines of $STATE/server.log:" >&2
    tail -20 "$STATE/server.log" 2>/dev/null | sed 's/^/    /' >&2 || true
    die "see: systemctl status $UNIT; journalctl -u $UNIT -n 50 --no-pager"
  fi
  printf '%s' "$URL" > "$STATE/server.url"
  info "healthy"

  # ── 5. Seed and check, through https, trusting only our CA ────────────────
  say "seeding the demo org through $URL (about 90 s)"
  export KEYORIX_SERVER="$URL" SSL_CERT_FILE="$CA_PUB" CURL_CA_BUNDLE="$CA_PUB" KEYORIX_CA_FILE="$CA_PUB"
  "$DIR/scripts/demo/seed-demo.sh" "$STATE" || die "seeding failed (the server keeps running; fix the cause and re-run with --reuse). Server log: $STATE/server.log"
  say "checking the demo (scripts/demo/check.sh --used)"
  local check_rc=0
  "$DIR/scripts/demo/check.sh" --url "$URL" --state "$STATE/state.env" --used --no-ui || check_rc=$?

  # ── 6. Summary ─────────────────────────────────────────────────────────────
  local ca_cmds="$DIR/keyorix-demo-ca.crt"
  cat <<EOF

================================================================================
 Keyorix demo box: $URL
 server:        systemctl status $UNIT   (log: $STATE/server.log)
 login:         admin with the public demo password (scripts/demo/seed-demo.sh); MFA is on:
                the TOTP setup key is in $STATE/admin-mfa (0600), logins in $STATE/state.env
 CA file:       $CA_PUB
 CA SHA-256:    $FP
 certificate:   renewed automatically (<30 days left): clients need nothing after trusting the CA once

 Trust the CA ONCE on each client (the only manual step). First copy it:
   scp root@$IP:$ca_cmds .
 macOS:    sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain keyorix-demo-ca.crt
 Windows:  certutil -addstore -f Root keyorix-demo-ca.crt        (administrator prompt)
 Debian/Ubuntu: sudo cp keyorix-demo-ca.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates
 RHEL/Fedora:   sudo cp keyorix-demo-ca.crt /etc/pki/ca-trust/source/anchors/ && sudo update-ca-trust
 Keyorix CLI:   keyorix config set ca_file \$PWD/keyorix-demo-ca.crt     (then: keyorix login --server $URL)
 Check the fingerprint above against: openssl x509 -in keyorix-demo-ca.crt -noout -fingerprint -sha256
 The CA only vouches for this box's address and names (X.509 nameConstraints).
================================================================================
EOF
  if [ "$check_rc" -ne 0 ]; then
    echo "ERROR: scripts/demo/check.sh --used did not end in DEMO READY (exit $check_rc); read its lines above. The box itself is up." >&2
    exit "$check_rc"
  fi
  echo "DEMO READY at $URL"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then main "$@"; fi
