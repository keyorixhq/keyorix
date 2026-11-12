#!/usr/bin/env bash
# Provision a small, throwaway LXC on a Proxmox host that runs PostgreSQL 17 plus a Go
# toolchain, for the SQLite-vs-PostgreSQL differential fuzzers
# (FuzzStorageBackendDifferentialV2, TestBackendDifferential*).
# See docs/fuzzing/pg-sqlite-differential.md.
#
# Run ON the Proxmox host (as root). Idempotent: re-running skips what already exists.
#   CTID=270 ./pg-differential-ct.sh
#
# Resources: 2 cores, 4 GiB RAM, no swap, 25 GiB rootfs, onboot=0 (does not auto-start).
# It never touches other containers/VMs. Postgres listens on localhost only; the
# harness runs INSIDE the container, so no port is published.
#
# The cluster is created with en_US.UTF-8 (what the official postgres Docker image and
# every mainstream distro default to), NOT the C locale: collation and LOWER()/UPPER()
# behaviour are exactly what a SQLite-vs-PostgreSQL differential needs to see.
set -euo pipefail

CTID="${CTID:-270}"
HOSTNAME_CT="${HOSTNAME_CT:-keyorix-pgdiff}"
TEMPLATE="${TEMPLATE:-local:vztmpl/debian-13-standard_13.1-2_amd64.tar.zst}"
STORAGE="${STORAGE:-local-hdd}"
DISK_GB="${DISK_GB:-25}"
GO_VERSION="${GO_VERSION:-1.27.4}" # must match go.mod's toolchain line (checked below)
# SHA-256 of go${GO_VERSION}.linux-amd64.tar.gz as published at go.dev/dl. Pinned for the
# default version; a different GO_VERSION must come with its own GO_SHA256.
GO_SHA256_1_27_4=7226736c2339719cda28fbf3a54d71aa63bcefe376e98cef00034268dab24840
if [ "$GO_VERSION" = "1.27.4" ]; then GO_SHA256="${GO_SHA256:-$GO_SHA256_1_27_4}"; fi
GO_SHA256="${GO_SHA256:-}"
PG_PASSWORD="${PG_PASSWORD:-difffuzz}"

if [ -z "$GO_SHA256" ]; then
  echo "GO_VERSION=$GO_VERSION has no pinned checksum: set GO_SHA256 to the value go.dev/dl publishes" >&2
  exit 2
fi
GOMOD="$(cd "$(dirname "$0")/../.." && pwd)/go.mod"
if [ -f "$GOMOD" ]; then
  want=$(sed -n 's/^toolchain go//p' "$GOMOD")
  if [ -n "$want" ] && [ "$want" != "$GO_VERSION" ]; then
    echo "GO_VERSION=$GO_VERSION does not match $GOMOD (toolchain go$want)" >&2
    exit 2
  fi
else
  echo "warning: $GOMOD not found, GO_VERSION=$GO_VERSION not checked against the repo" >&2
fi

if pct status "$CTID" >/dev/null 2>&1; then
  echo "CT $CTID already exists; skipping create"
else
  pct create "$CTID" "$TEMPLATE" \
    --hostname "$HOSTNAME_CT" --cores 2 --memory 4096 --swap 0 \
    --rootfs "${STORAGE}:${DISK_GB}" --unprivileged 1 --features nesting=1 \
    --net0 name=eth0,bridge=vmbr0,ip=dhcp --onboot 0 \
    --description "SQLite-vs-PostgreSQL differential fuzzing (throwaway). Safe to destroy."
fi
pct status "$CTID" | grep -q running || pct start "$CTID"
sleep 8

pct exec "$CTID" -- env PG_PASSWORD="$PG_PASSWORD" GO_VERSION="$GO_VERSION" GO_SHA256="$GO_SHA256" bash -s <<'INNER'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive LC_ALL=C
apt-get update -qq
apt-get install -y -qq postgresql postgresql-client git ca-certificates curl build-essential rsync locales >/dev/null
sed -i 's/^# *en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen
locale-gen >/dev/null
PGV=$(ls /etc/postgresql | head -1)
COLL=$(su postgres -c "psql -tAc \"select datcollate from pg_database where datname='postgres'\"" 2>/dev/null || true)
if [ "$COLL" != "en_US.UTF-8" ]; then
  pg_dropcluster --stop "$PGV" main 2>/dev/null || true
  pg_createcluster --locale en_US.UTF-8 "$PGV" main
fi
CONF=/etc/postgresql/$PGV/main/postgresql.conf
# Throwaway data: trade durability for speed. max_connections for the concurrency test.
sed -i "s/^#\?fsync.*/fsync = off/; s/^#\?synchronous_commit.*/synchronous_commit = off/; s/^#\?full_page_writes.*/full_page_writes = off/; s/^#\?max_connections.*/max_connections = 200/" "$CONF"
systemctl enable postgresql >/dev/null 2>&1 || true
pg_ctlcluster "$PGV" main restart || pg_ctlcluster "$PGV" main start
su postgres -c "psql -tAc \"select 1 from pg_roles where rolname='difffuzz'\"" | grep -q 1 || \
  su postgres -c "psql -c \"create role difffuzz login superuser password '${PG_PASSWORD}'\""
su postgres -c "psql -tAc \"select 1 from pg_database where datname='difffuzz'\"" | grep -q 1 || \
  su postgres -c "createdb -O difffuzz difffuzz"
if [ ! -x /usr/local/go/bin/go ]; then
  tgz=/root/go${GO_VERSION}.linux-amd64.tar.gz
  curl -fsSL -o "$tgz" "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
  echo "${GO_SHA256}  ${tgz}" | sha256sum -c - || { echo "Go toolchain checksum mismatch; not installing" >&2; rm -f "$tgz"; exit 1; }
  tar -C /usr/local -xzf "$tgz"
  rm -f "$tgz"
fi
echo "collation: $(su postgres -c "psql -tAc \"select datcollate from pg_database where datname='difffuzz'\"")"
INNER
echo "Ready. Inside the CT: export PATH=\$PATH:/usr/local/go/bin KEYORIX_TEST_PG_DSN='postgres://difffuzz:${PG_PASSWORD}@127.0.0.1:5432/difffuzz?sslmode=disable'"
