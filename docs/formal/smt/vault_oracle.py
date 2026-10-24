#!/usr/bin/env python3
"""Check the reference evaluator (vaultsmt.vault_allows) against a REAL Vault/OpenBao.

The SMT encoding is tested against vault_allows (test_vaultsmt.py); this script closes
the remaining gap by asking Vault itself. For every case model it writes the case's
policies into Vault, mints a token holding exactly them, and compares
sys/capabilities-self with vault_allows on: every counterexample check.py finds, plus a
fixed probe list per case (paths inside, beside and above each rule).

Needs a THROWAWAY dev-mode Vault (it writes ACL policies and tokens):
    docker run -d --rm --name smt-oracle -p 127.0.0.1:8200:8200 \
        -e VAULT_DEV_ROOT_TOKEN_ID=smt-oracle-root hashicorp/vault:1.15
    VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN_FILE=./root.token \
        python3 docs/formal/smt/vault_oracle.py

The token is read from the file VAULT_TOKEN_FILE names (never argv). Exit 1 on any
disagreement, printing each one.
"""

import glob
import json
import os
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vaultsmt as vs  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))


def call(addr, token, method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(addr + "/v1/" + path, data=data, method=method,
                                 headers={"X-Vault-Token": token, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 -- operator-supplied local Vault
        raw = resp.read()
    return json.loads(raw) if raw else {}


def hcl(rules):
    return "\n".join('path "%s" { capabilities = [%s] }'
                     % (r["path"], ", ".join('"%s"' % c for c in r["capabilities"])) for r in rules)


def probes(model):
    out = set()
    for r in model["vault_rules"]:
        head = vs._literal_head(r["path"])
        for suffix in ("", "x", "x/", "x/y", "a/b/c"):
            out.add(head + suffix)
        out.add(head.rstrip("/"))
    return sorted(p for p in out if p and "{{" not in p)


def main():
    addr = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
    with open(os.environ["VAULT_TOKEN_FILE"]) as f:
        root = f.read().strip()
    disagreements = checked = 0
    for path in sorted(glob.glob(os.path.join(HERE, "cases", "*.model.json"))):
        model = vs.load(path)
        names = []
        by_policy = {}
        for r in model["vault_rules"]:
            by_policy.setdefault(r["policy"], []).append(r)
        for pol, rules in by_policy.items():
            name = "smt-%s-%s" % (model["case"], pol)
            call(addr, root, "PUT", "sys/policies/acl/" + name, {"policy": hcl(rules)})
            names.append(name)
        tok = call(addr, root, "POST", "auth/token/create",
                   {"policies": names, "no_default_policy": True, "ttl": "10m"})["auth"]["client_token"]
        acl = vs.merge_rules(model["vault_rules"])
        reqs = [(p, c) for p in probes(model) for c in vs.CAPS]
        reqs += [(cx["vault_path"], cx["capability"]) for cx in vs.check_case(model).counterexamples]
        for p, c in reqs:
            caps = call(addr, tok, "POST", "sys/capabilities-self", {"paths": [p]}).get("capabilities", [])
            real = c in caps and "deny" not in caps
            ours = vs.vault_allows(acl, p, c)
            checked += 1
            if real != ours:
                disagreements += 1
                print("DISAGREE %s: %s on %s: vault=%s vaultsmt=%s (caps %s)"
                      % (model["case"], c, p, real, ours, caps))
    print("%d requests checked against %s, %d disagreements" % (checked, addr, disagreements))
    return 1 if disagreements else 0


if __name__ == "__main__":
    sys.exit(main())
