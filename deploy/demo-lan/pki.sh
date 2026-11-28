#!/usr/bin/env bash
# deploy/demo-lan/pki.sh — a local CA plus a server certificate for a LAN / air-gapped demo box.
# openssl only: no ACME, no public DNS, no server needed. install.sh runs it; the systemd unit
# runs `renew` before every start and a timer runs it daily.
#
#   pki.sh init  --ca-dir D --leaf-dir D --ip IP [--ip IP]... --dns NAME [--dns NAME]... [--new-ca] [--key-group G]
#   pki.sh renew --ca-dir D --leaf-dir D [--restart-unit UNIT] [--key-group G]
#   pki.sh check --ca-dir D --leaf-dir D
#
# The CA is created ONCE (ECDSA P-256, 10 years, key 0600 in a 0700 directory) and is limited
# to TLS server certificates for this box:
#   - extendedKeyUsage = serverAuth on the CA itself, so clients that check it (browsers, Go,
#     OpenSSL with a purpose) refuse a client, code-signing or e-mail certificate it signs;
#   - a critical X.509 nameConstraints extension that permits only the IPs and DNS names given
#     to `init` (plus localhost and 127.0.0.1), and no e-mail address or URI at all.
# What a DNS constraint cannot express: it also permits every name BELOW it (x.demo-box.lan,
# x.localhost), so whoever holds the CA key can sign those too. The CA key signs the server
# certificate and nothing else.
#
# The server certificate (ECDSA P-256, serverAuth, SAN = the names, 820 days: under the 825-day
# cap of Apple and Chrome, and never past the CA's own end) is re-issued when fewer than 30 days
# are left, when it is missing, does not chain to the CA, or does not match its key. Clients
# trust the CA once; a renewal needs nothing on any client. Whatever a re-issue replaces is moved
# to <leaf-dir>/old/<utc time>/, never deleted. When the CA itself has fewer than 90 days left,
# every command prints a WARNING (re-run install.sh --reuse --new-ca); once it has expired no
# certificate can be issued and `renew` fails with that instruction.
#
#   check   exit 0 when the certificate is valid for more than the renewal threshold (or for as
#           long as the CA allows), chains to the CA and matches its key; exit 1 otherwise.
#   renew   re-issue when `check` fails; prints "pki: certificate ok ..." or "pki: renewed ...".
#           --restart-unit UNIT: after a renewal, `systemctl try-restart UNIT` (the timer uses it).
#   --key-group G  (init, renew) the server runs as a member of group G, not as root: the
#           certificate key is root:G 0640 in a root:G 0750 leaf directory. Without it, 0600.
#   init    create the CA if missing, then issue the certificate if it is missing, due, or does
#           not carry exactly the requested names. If the CA exists but does not permit a
#           requested name (the box got a new address) it refuses: --new-ca moves the old CA
#           aside (kept) and creates a new one, which every client must then trust again.
#
# Tunables (environment, used by the tests): KEYORIX_LAN_LEAF_DAYS (820), KEYORIX_LAN_RENEW_DAYS
# (30), KEYORIX_LAN_CA_DAYS (3650), KEYORIX_LAN_CA_WARN_DAYS (90).
set -euo pipefail

LEAF_DAYS="${KEYORIX_LAN_LEAF_DAYS:-820}"
RENEW_DAYS="${KEYORIX_LAN_RENEW_DAYS:-30}"
CA_DAYS="${KEYORIX_LAN_CA_DAYS:-3650}"
CA_WARN_DAYS="${KEYORIX_LAN_CA_WARN_DAYS:-90}"

say() { echo "pki: $*"; }
die() { echo "pki: ERROR: $*" >&2; exit 1; }

command -v openssl >/dev/null 2>&1 || die "openssl is required (apt install openssl / dnf install openssl)"

CMD="${1:-}"
[ -n "$CMD" ] || die "usage: pki.sh init|renew|check --ca-dir D --leaf-dir D ... (see the header of this file)"
shift
CA_DIR="" LEAF_DIR="" NEW_CA=false RESTART_UNIT="" KEY_GROUP=""
IPS=() DNSS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --ca-dir)       [ $# -ge 2 ] || die "--ca-dir needs a value"; CA_DIR="$2"; shift 2 ;;
    --leaf-dir)     [ $# -ge 2 ] || die "--leaf-dir needs a value"; LEAF_DIR="$2"; shift 2 ;;
    --ip)           [ $# -ge 2 ] || die "--ip needs a value"; IPS+=("$2"); shift 2 ;;
    --dns)          [ $# -ge 2 ] || die "--dns needs a value"; DNSS+=("$2"); shift 2 ;;
    --restart-unit) [ $# -ge 2 ] || die "--restart-unit needs a value"; RESTART_UNIT="$2"; shift 2 ;;
    --key-group)    [ $# -ge 2 ] || die "--key-group needs a value"; KEY_GROUP="$2"; shift 2 ;;
    --new-ca)       NEW_CA=true; shift ;;
    -h|--help)      grep '^#' "$0" | sed 's/^# \?//'; exit 0 ;;
    *)              die "unknown argument: $1" ;;
  esac
done
if [ -z "$CA_DIR" ] || [ -z "$LEAF_DIR" ]; then die "--ca-dir and --leaf-dir are required"; fi
if [ -n "$KEY_GROUP" ] && [[ ! "$KEY_GROUP" =~ ^[a-z_][a-z0-9_-]*$ ]]; then die "--key-group is not a group name: $KEY_GROUP"; fi

CA_KEY="$CA_DIR/ca.key"; CA_CRT="$CA_DIR/ca.crt"; CA_NAMES="$CA_DIR/names"
LEAF_KEY="$LEAF_DIR/server.key"; LEAF_CRT="$LEAF_DIR/server.crt"; LEAF_NAMES="$LEAF_DIR/names"

# Names end up inside an openssl config file: accept only plain IPv4 and DNS labels.
valid_ip()  { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && [ "$(printf '%s' "$1" | tr '.' '\n' | sort -n | tail -1)" -le 255 ]; }
valid_dns() { [[ "$1" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] && [ "${#1}" -le 253 ]; }

# normalise_names fills NAMES (sorted, unique, "IP:x" / "DNS:y" lines) from IPS/DNSS plus the
# two names that are always valid for this box.
normalise_names() {
  local n
  for n in ${IPS[@]+"${IPS[@]}"}; do valid_ip "$n" || die "not an IPv4 address: $n"; done
  for n in ${DNSS[@]+"${DNSS[@]}"}; do valid_dns "$n" || die "not a usable DNS name: $n"; done
  NAMES="$( { for n in ${IPS[@]+"${IPS[@]}"} 127.0.0.1; do printf 'IP:%s\n' "$n"; done
              for n in ${DNSS[@]+"${DNSS[@]}"} localhost; do printf 'DNS:%s\n' "$(printf '%s' "$n" | tr '[:upper:]' '[:lower:]')"; done; } | sort -u )"
}

# san_section / nc_section print the [section] bodies for an openssl config from a NAMES list.
san_section() {
  local i=0 l
  while IFS= read -r l; do
    i=$((i + 1))
    case "$l" in IP:*) printf 'IP.%d = %s\n' "$i" "${l#IP:}" ;; DNS:*) printf 'DNS.%d = %s\n' "$i" "${l#DNS:}" ;; esac
  done <<<"$1"
}
nc_section() {
  local i=0 l
  while IFS= read -r l; do
    i=$((i + 1))
    case "$l" in
      IP:*)  printf 'permitted;IP.%d = %s/255.255.255.255\n' "$i" "${l#IP:}" ;;
      DNS:*) printf 'permitted;DNS.%d = %s\n' "$i" "${l#DNS:}" ;;
    esac
  done <<<"$1"
}

new_key() { # new_key FILE: ECDSA P-256, 0600 from the first byte
  ( umask 077; openssl ecparam -name prime256v1 -genkey -noout -out "$1" 2>/dev/null ) || die "openssl could not generate an ECDSA P-256 key"
  chmod 600 "$1"
}

stamp() { date -u +%Y%m%dT%H%M%SZ; }

work=""
drop_work() { [ -z "$work" ] || rm -rf "$work"; work=""; }   # only the private work dir this run created
trap drop_work EXIT

# names_permitted REQUESTED PERMITTED: every requested name is in the permitted list.
names_permitted() {
  local l
  while IFS= read -r l; do
    printf '%s\n' "$2" | grep -qxF "$l" || return 1
  done <<<"$1"
}

ensure_ca() {
  mkdir -p "$CA_DIR"; chmod 700 "$CA_DIR"
  if [ -s "$CA_KEY" ] && [ -s "$CA_CRT" ]; then
    local have; have="$(cat "$CA_NAMES" 2>/dev/null || true)"
    if names_permitted "$NAMES" "$have"; then
      say "CA exists ($CA_CRT) and permits every requested name: kept"
      return 0
    fi
    [ "$NEW_CA" = true ] || die "the existing CA ($CA_CRT) is limited to: $(printf '%s' "$have" | tr '\n' ' ')
       and does not permit: $(printf '%s' "$NAMES" | tr '\n' ' ')
       (the box has a new address or name). To get a new CA re-run with --new-ca; the old one is kept
       under $CA_DIR/old/ and every client then has to trust the new CA once."
    local dest; dest="$CA_DIR/old/$(stamp)"
    mkdir -p "$dest"; chmod 700 "$CA_DIR/old" "$dest"
    mv "$CA_KEY" "$CA_CRT" "$dest/"; [ ! -f "$CA_NAMES" ] || mv "$CA_NAMES" "$dest/"
    say "old CA moved to $dest (kept)"
  elif [ -e "$CA_KEY" ] || [ -e "$CA_CRT" ]; then
    die "only one of $CA_KEY and $CA_CRT exists: refusing to guess; move both aside (they are not deleted by this script)"
  fi
  work="$(mktemp -d "$CA_DIR/.work.XXXXXX")"
  local suffix; suffix="$(openssl rand -hex 4)"
  local cn; cn="Keyorix demo LAN CA ${DNSS[0]:-box} $suffix"
  {
    printf '[req]\ndistinguished_name = dn\nprompt = no\nx509_extensions = v3_ca\n'
    printf '[dn]\nCN = %s\n' "$cn"
    printf '[v3_ca]\nbasicConstraints = critical, CA:TRUE, pathlen:0\nkeyUsage = critical, keyCertSign, cRLSign\n'
    printf 'subjectKeyIdentifier = hash\nnameConstraints = critical, @nc\n'
    printf 'extendedKeyUsage = serverAuth\n'
    printf '[nc]\n'; nc_section "$NAMES"
    # A permitted subtree that no real name is in: no e-mail address and no URI passes.
    printf 'permitted;email.0 = .invalid\npermitted;URI.0 = .invalid\n'
  } > "$work/ca.cnf"
  new_key "$work/ca.key"
  ( umask 077; openssl req -new -x509 -sha256 -days "$CA_DAYS" -key "$work/ca.key" -config "$work/ca.cnf" -out "$work/ca.crt" ) \
    || die "openssl could not create the CA"
  chmod 644 "$work/ca.crt"
  mv "$work/ca.key" "$CA_KEY"; mv "$work/ca.crt" "$CA_CRT"
  printf '%s\n' "$NAMES" > "$CA_NAMES"; chmod 644 "$CA_NAMES"
  drop_work
  say "created the CA ($cn), valid $CA_DAYS days, limited to: $(printf '%s' "$NAMES" | tr '\n' ' ')"
}

# valid_for CERT SECONDS: CERT is still valid SECONDS from now.
valid_for() { openssl x509 -in "$1" -noout -checkend "$2" >/dev/null 2>&1; }
end_date() { openssl x509 -in "$1" -noout -enddate | sed 's/^notAfter=//'; }

# days_left CERT MAX prints the whole days (0..MAX) CERT stays valid from now, or -1 when it has
# expired. openssl only: no date arithmetic, which differs between GNU and BSD date.
days_left() {
  local lo=0 hi="$2" mid
  valid_for "$1" 0 || { echo -1; return 0; }
  if valid_for "$1" $(($2 * 86400)); then echo "$2"; return 0; fi
  while [ $((hi - lo)) -gt 1 ]; do # valid lo days from now, not valid hi days from now
    mid=$(((lo + hi) / 2))
    if valid_for "$1" $((mid * 86400)); then lo=$mid; else hi=$mid; fi
  done
  echo "$lo"
}

# ca_expiry_warning: a WARNING on stderr when the CA ends within CA_WARN_DAYS.
ca_expiry_warning() {
  [ -s "$CA_CRT" ] || return 0
  ! valid_for "$CA_CRT" $((CA_WARN_DAYS * 86400)) || return 0
  echo "pki: WARNING: the local CA $CA_CRT ends $(end_date "$CA_CRT") (fewer than $CA_WARN_DAYS days left)." \
    "Before then re-run install.sh with --reuse --new-ca and trust the new CA on every client once;" \
    "after it has expired no server certificate can be issued." >&2
}

# leaf_problem prints why the certificate needs (re-)issuing and returns 0, or returns 1 when fine.
leaf_problem() {
  if [ ! -s "$LEAF_CRT" ] || [ ! -s "$LEAF_KEY" ]; then echo "no certificate yet"; return 0; fi
  [ -s "$CA_CRT" ] || { echo "no CA at $CA_CRT"; return 0; }
  if ! valid_for "$LEAF_CRT" $((RENEW_DAYS * 86400)); then
    # Re-issue only when that gains at least a day: a new certificate would get CAP whole days
    # (issue_leaf caps it to the CA), so it is worth it only when this one ends more than a day
    # before that. Otherwise (the CA bounds both) re-issuing on every start would only pile up
    # old/ copies; ca_expiry_warning says what to do instead. An expired one is always due.
    local cap; cap="$(days_left "$CA_CRT" "$LEAF_DAYS")"
    if ! valid_for "$LEAF_CRT" 0 || { [ "$cap" -ge 1 ] && ! valid_for "$LEAF_CRT" $(((cap - 1) * 86400)); }; then
      echo "fewer than $RENEW_DAYS days left (notAfter $(end_date "$LEAF_CRT"))"; return 0
    fi
  fi
  openssl verify -CAfile "$CA_CRT" "$LEAF_CRT" >/dev/null 2>&1 || { echo "does not verify against $CA_CRT"; return 0; }
  local a b
  a="$(openssl x509 -in "$LEAF_CRT" -noout -pubkey 2>/dev/null)"; b="$(openssl pkey -in "$LEAF_KEY" -pubout 2>/dev/null)"
  if [ -z "$a" ] || [ "$a" != "$b" ]; then echo "certificate and key do not match"; return 0; fi
  return 1
}

# leaf_perms: with --key-group the server (a member of KEY_GROUP, not root) can read the key and
# nobody else can. Idempotent, so a renew also fixes the modes of an older install.
leaf_perms() {
  if [ -z "$KEY_GROUP" ]; then chmod 755 "$LEAF_DIR"; return 0; fi
  chgrp "$KEY_GROUP" "$LEAF_DIR" || die "could not give $LEAF_DIR to group $KEY_GROUP"
  chmod 750 "$LEAF_DIR"
  if [ -e "$LEAF_KEY" ]; then chgrp "$KEY_GROUP" "$LEAF_KEY"; chmod 640 "$LEAF_KEY"; fi
}

issue_leaf() { # issue_leaf NAMES
  local names="$1" cn days
  valid_for "$CA_CRT" 86400 || die "the local CA $CA_CRT ends $(end_date "$CA_CRT"): a certificate it signs would expire with it.
       Re-run install.sh with --reuse --new-ca (the old CA is kept) and trust the new CA on every client once."
  days="$(days_left "$CA_CRT" "$LEAF_DAYS")"
  [ "$days" -ge "$LEAF_DAYS" ] || say "certificate validity capped to $days days: the CA ends $(end_date "$CA_CRT")"
  mkdir -p "$LEAF_DIR"; leaf_perms
  work="$(mktemp -d "$LEAF_DIR/.work.XXXXXX")"
  cn="$(printf '%s\n' "$names" | sed -n 's/^DNS://p' | head -1)"
  {
    printf '[req]\ndistinguished_name = dn\nprompt = no\n[dn]\nCN = %s\n' "${cn:-keyorix-demo}"
    printf '[v3_leaf]\nbasicConstraints = critical, CA:FALSE\nkeyUsage = critical, digitalSignature\nextendedKeyUsage = serverAuth\n'
    printf 'subjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid\nsubjectAltName = @san\n'
    printf '[san]\n'; san_section "$names"
  } > "$work/leaf.cnf"
  new_key "$work/server.key"
  openssl req -new -key "$work/server.key" -config "$work/leaf.cnf" -out "$work/server.csr" || die "openssl could not create the certificate request"
  openssl x509 -req -sha256 -days "$days" -in "$work/server.csr" -CA "$CA_CRT" -CAkey "$CA_KEY" \
    -set_serial "0x$(openssl rand -hex 16)" -extfile "$work/leaf.cnf" -extensions v3_leaf -out "$work/server.crt" >/dev/null 2>&1 \
    || die "openssl could not sign the server certificate with the CA"
  openssl verify -CAfile "$CA_CRT" "$work/server.crt" >/dev/null 2>&1 \
    || die "the new certificate does not verify against the CA (a name outside the CA's constraints?)"
  chmod 600 "$work/server.key"; chmod 644 "$work/server.crt"
  if [ -e "$LEAF_CRT" ] || [ -e "$LEAF_KEY" ]; then
    local dest; dest="$LEAF_DIR/old/$(stamp)"
    mkdir -p "$dest"; chmod 700 "$LEAF_DIR/old" "$dest"
    [ ! -e "$LEAF_CRT" ] || mv "$LEAF_CRT" "$dest/"
    [ ! -e "$LEAF_KEY" ] || mv "$LEAF_KEY" "$dest/"
    [ ! -e "$LEAF_NAMES" ] || cp -p "$LEAF_NAMES" "$dest/"
    say "previous certificate moved to $dest (kept)"
  fi
  mv "$work/server.key" "$LEAF_KEY"; mv "$work/server.crt" "$LEAF_CRT"
  leaf_perms
  printf '%s\n' "$names" > "$LEAF_NAMES"; chmod 644 "$LEAF_NAMES"
  drop_work
  say "issued $LEAF_CRT for $(printf '%s' "$names" | tr '\n' ' '), $days days, signed by the local CA"
}

case "$CMD" in
  check)
    ca_expiry_warning
    if why="$(leaf_problem)"; then say "certificate needs attention: $why"; exit 1; fi
    say "certificate ok (valid until $(end_date "$LEAF_CRT"))"
    ;;
  renew)
    if [ ! -s "$CA_KEY" ] || [ ! -s "$CA_CRT" ]; then die "no CA in $CA_DIR (run install.sh first)"; fi
    ca_expiry_warning
    if why="$(leaf_problem)"; then
      say "re-issuing the certificate: $why"
      names="$(cat "$LEAF_NAMES" 2>/dev/null || cat "$CA_NAMES")"
      issue_leaf "$names"
      say "renewed: clients that trust the CA need nothing"
      if [ -n "$RESTART_UNIT" ]; then
        if command -v systemctl >/dev/null 2>&1 && systemctl try-restart "$RESTART_UNIT"; then
          say "restarted $RESTART_UNIT to load it"
        else
          echo "pki: WARNING: could not restart $RESTART_UNIT; restart it to load the new certificate" >&2
        fi
      fi
    else
      leaf_perms
      say "certificate ok (valid until $(end_date "$LEAF_CRT"); renewed when fewer than $RENEW_DAYS days are left)"
    fi
    ;;
  init)
    [ ${#IPS[@]} -gt 0 ] || die "init needs at least one --ip"
    normalise_names
    ensure_ca
    ca_expiry_warning
    have="$(cat "$LEAF_NAMES" 2>/dev/null || true)"
    if why="$(leaf_problem)"; then
      issue_leaf "$NAMES"
    elif [ "$have" != "$NAMES" ]; then
      say "certificate names differ from the requested ones: re-issuing"
      issue_leaf "$NAMES"
    else
      leaf_perms
      say "certificate ok (valid until $(end_date "$LEAF_CRT")): kept"
    fi
    ;;
  *) die "unknown command: $CMD (init, renew or check)" ;;
esac
