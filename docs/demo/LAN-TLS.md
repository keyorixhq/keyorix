# A demo box on a LAN or an air-gapped network, with HTTPS in one command

`deploy/demo-lan/install.sh` turns a Linux box with systemd into a seeded Keyorix demo
served over HTTPS, with no ACME, no public DNS and no manual openssl. It is for a homelab,
a pilot on a closed network, or any place a public certificate authority cannot reach. For a
demo on an internet-facing VM (Docker, Caddy, ACME) use `deploy/demo-hosted` instead.

## What you need

- A Linux box with systemd, `openssl`, `python3` and `curl`, and root.
- A checkout (or release tarball) of this repository on that box: the installer copies
  `scripts/demo` and `docs/demo/GOLDEN-PATH.md` from it.
- Linux builds of the three binaries, in one directory (build them anywhere with Go; use the
  box's architecture, `amd64` shown):

```sh
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o out/keyorix-server ./server
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 GOWORK=off go -C cli build -o ../out/keyorix .
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 GOWORK=off go build -o out/totpgen ./scripts/totpgen/main.go
```

## Install

```sh
sudo deploy/demo-lan/install.sh --bin-dir ./out
```

Options: `--dir` (default `/opt/keyorix-demo`), `--port` (default 8080), `--hostname NAME`
(one more DNS name for the certificate), `--ip ADDR` (only for a box with several
addresses), `--reuse`, `--new-ca`.

It detects the box's own address (`ip route get`, else `hostname -I`); nothing is hard-coded.
At the end it prints the URL, the CA file, the CA's SHA-256 fingerprint and the trust commands
below, with `DEMO READY` when `scripts/demo/check.sh --used` passes. It takes a few minutes: the
seed is about 90 s and the check a few more.

## Trust the CA once (the only manual step)

Copy the CA from the box (the installer prints the exact line), compare its fingerprint with the
one printed, then:

| Where | Command |
|---|---|
| macOS | `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain keyorix-demo-ca.crt` |
| Windows (administrator prompt) | `certutil -addstore -f Root keyorix-demo-ca.crt` |
| Debian / Ubuntu | `sudo cp keyorix-demo-ca.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates` |
| RHEL / Fedora | `sudo cp keyorix-demo-ca.crt /etc/pki/ca-trust/source/anchors/ && sudo update-ca-trust` |
| Keyorix CLI | `keyorix config set ca_file $PWD/keyorix-demo-ca.crt` |

Firefox keeps its own store: Settings, Privacy & Security, Certificates, Import (or set
`security.enterprise_roots.enabled` to use the OS store).

## What is on the box

```
/opt/keyorix-demo/
  keyorix-demo-ca.crt     the CA certificate to hand out (public)
  bin/                    keyorix, keyorix-server, totpgen
  scripts/demo/, docs/demo/   copied from the checkout; seed and check run from here
  pki/ca/                 ca.key (0600, directory 0700) and ca.crt: used to sign the server certificate, nothing else
  pki/leaf/               server.crt, server.key (0600); replaced certificates are kept in old/<time>/
  env                     0600 EnvironmentFile: master password, bootstrap token (generated, never printed)
  state/                  keyorix.yaml, keyorix.db, server.log, state.env, admin-mfa (0600), install.log
  backup-<time>/          anything a re-run replaced
```

The unit is `keyorix-lan-<dir name>.service` (`Restart=always`, enabled), with a daily
`...-renew.timer`.

## The certificate

- The CA is created once: ECDSA P-256, 10 years, key mode 0600, `basicConstraints CA:TRUE,
  pathlen:0`, and a critical **nameConstraints** extension that permits only this box's address
  and names plus `localhost` and `127.0.0.1`. A client that trusts it does not thereby trust it
  for any other site. The CA key signs the server certificate and nothing else.
- The server certificate (ECDSA P-256, `serverAuth`, SAN: address, hostname, `localhost`,
  `127.0.0.1`) is valid 820 days, under the 825-day cap of Apple and Chrome.
- It is re-issued when fewer than 30 days are left: before every start of the server and by
  the daily timer (which then restarts the server). The CA does not change, so **clients need
  nothing at renewal**.
- If the box gets a new address, the old CA cannot sign for it. `install.sh --reuse --new-ca`
  makes a new CA (the old one is kept in `pki/ca/old/`) and every client trusts the new CA once.

## Re-running, upgrading, safety

- With an existing `state/keyorix.db` the installer refuses and changes nothing. `--reuse` keeps
  the config, data and secrets and refreshes the binaries, scripts, certificate and unit (the
  seed is idempotent). Replaced files are copied to `backup-<time>/`; nothing is deleted.
- A port that is already in use, a missing binary, a macOS binary instead of a Linux one, no
  systemd, or not being root each stop it with a message before anything is written.
- The demo logins are the repository's public demo passwords, with MFA on (the TOTP setup key is
  in `state/admin-mfa`). `/metrics` is protected by a generated token; rate limiting stays as the
  demo config sets it. Keep the box off untrusted networks.

## Not covered

- The installer does not try to run on a box without systemd; run the steps of
  `scripts/demo/native-up.sh` by hand there and use `deploy/demo-lan/pki.sh` for the certificate.
- IPv6 addresses are not put into the certificate.
- This is the demo mechanism. The production TLS bootstrap is designed separately
  (TLS-BOOTSTRAP-1) and may reuse this one's pieces.
