"""Vault ACL vs Keyorix grants as an SMT subset check (RD-SMT-SPIKE-1).

Question asked of the solver, per case (one Vault role's attached policy set and the
Keyorix grants keyorix-migrate proposes for it):

    exists op, mount, secret name:  Keyorix allows (op, secret)  and  Vault denies it

SAT = the migration widens access, and the model is a concrete request to show.
UNSAT = Keyorix grants are a subset of the Vault policy for every secret name, including
names that do not exist yet (the solver quantifies over all strings, not a sample).

Encoding choices (docs/design/smt-vault-policy-equivalence.md has the reasoning):

* The universe is LOGICAL operations on a KV secret (read value, list names, read
  metadata, create, update, delete), not raw Vault paths: one logical operation becomes
  a different Vault request per KV version (v2 reads go to <mount>/data/<name>, listing to
  <mount>/metadata/<dir>) and a Keyorix permission on the secret's (project, environment).
  Comparing raw path strings would miss exactly the data/metadata split.
* A secret name is split into directory part d ("" or segments ending in "/") and a
  non-empty leaf without "/". Both are free string variables over the full alphabet.
* Vault matching is a string-regex membership per rule (exact: equality; "+" segment:
  [^/]*; trailing "*": any suffix). Vault's rule selection (exact first, then the
  highest-priority glob by Vault's documented "priority matching" order) depends only
  on the pattern strings, so it is resolved here at encoding time and emitted as one
  ite-chain: the first matching rule decides, deny inside it denies.
* Policies are merged the way Vault merges them: the same path in two policies unions
  capabilities, and deny on that same path wins.
* Keyorix: a grant covers a secret when the secret's import scope (the --vault-mount /
  --vault-path -> --project/--environment run that imported it) equals the grant's
  project and the grant's environment is that environment or 0 (all environments).
  A secret no import covers does not exist in Keyorix and is never Keyorix-allowed.

Not modelled (each one is stated in the design note): Sentinel/EGP, templated paths
(treated as literal text, so they match nothing real), allowed_parameters/
denied_parameters/required_parameters, min/max_wrapping_ttl, response-wrapping, the
"patch" and "sudo" capabilities (sudo stanzas are Unmappable upstream), namespaces,
Keyorix secret sharing/ACL entries and native Keyorix secrets that never came from Vault.
"""

import json
import re
import shutil
import subprocess
import time

OPS = ["read", "list", "read_metadata", "create", "update", "delete"]
CAPS = ["read", "list", "create", "update", "delete"]
OP_CAP = {"read": "read", "list": "list", "read_metadata": "read",
          "create": "create", "update": "update", "delete": "delete"}
KEYORIX_PERM = {"read": "secrets.read", "list": "secrets.read", "read_metadata": "secrets.read",
                "create": "secrets.write", "update": "secrets.write", "delete": "secrets.delete"}


# ---------------------------------------------------------------- Vault semantics

def merge_rules(rules):
    """Merge stanzas from all attached policies into one ACL, as Vault does.

    Returns a list of {"path", "caps"} (caps a frozenset), one per distinct path."""
    merged = {}
    order = []
    for r in rules:
        caps = set(r["capabilities"])
        if r["path"] not in merged:
            merged[r["path"]] = set()
            order.append(r["path"])
        cur = merged[r["path"]]
        if "deny" in cur or "deny" in caps:
            merged[r["path"]] = {"deny"}
        else:
            cur |= caps
    return [{"path": p, "caps": frozenset(merged[p])} for p in order]


def _segments(pattern):
    return pattern.split("/")


def is_glob(pattern):
    return pattern.endswith("*")


def plus_count(pattern):
    return sum(1 for s in _segments(pattern) if s == "+")


def is_exact(pattern):
    return not is_glob(pattern) and plus_count(pattern) == 0


def first_wildcard(pattern):
    """Index of the first "+" segment or the trailing "*" (len if none)."""
    pos = 0
    for s in _segments(pattern):
        if s == "+":
            return pos
        pos += len(s) + 1
    return len(pattern) - 1 if is_glob(pattern) else len(pattern)


def priority_key(pattern):
    """Larger key = higher priority, per Vault's "priority matching" rules:
    1. the first wildcard ("+" or "*") later wins; 2. not ending in "*" wins;
    3. fewer "+" segments wins; 4. longer wins; 5. lexicographically larger wins."""
    return (first_wildcard(pattern), not is_glob(pattern), -plus_count(pattern),
            len(pattern), pattern)


def _py_regex(pattern):
    segs = _segments(pattern)
    parts = []
    for i, s in enumerate(segs):
        last = i == len(segs) - 1
        if s == "+":
            parts.append("[^/]*")
        elif last and s.endswith("*"):
            parts.append(re.escape(s[:-1]) + ".*")
        else:
            parts.append(re.escape(s))
    return re.compile("/".join(parts), re.S)


def ordered_rules(acl):
    """The ACL in Vault's selection order: exact rules, then globs by priority."""
    exact = [r for r in acl if is_exact(r["path"])]
    wild = sorted((r for r in acl if not is_exact(r["path"])),
                  key=lambda r: priority_key(r["path"]), reverse=True)
    return exact, wild


def select_rule(acl, path, cap):
    exact, wild = ordered_rules(acl)
    for r in exact:
        if r["path"] == path:
            return r
    if cap == "list" and path.endswith("/"):
        for r in exact:
            if r["path"] == path[:-1]:
                return r
    for r in wild:
        if _py_regex(r["path"]).fullmatch(path):
            return r
    return None


def vault_allows(acl, path, cap):
    """Concrete reference evaluator: does this merged ACL allow cap on path?"""
    r = select_rule(acl, path, cap)
    return r is not None and "deny" not in r["caps"] and cap in r["caps"]


def vault_request(kv_version, mount, op, name):
    """The (path, capability) Vault checks for a logical op, or None if n/a."""
    d = name[: name.rfind("/") + 1]
    if kv_version == 2:
        path = {"read": mount + "data/" + name, "list": mount + "metadata/" + d,
                "read_metadata": mount + "metadata/" + name}.get(op, mount + "data/" + name)
    else:
        if op == "read_metadata":
            return None
        path = mount + d if op == "list" else mount + name
    return path, OP_CAP[op]


# ---------------------------------------------------------------- Keyorix semantics

def _sorted_imports(model):
    return sorted(model["imports"], key=lambda i: (i["mount"], -len(i["path_prefix"])))


def keyorix_scope(model, mount, name):
    for imp in _sorted_imports(model):
        if imp["mount"] == mount and name.startswith(imp["path_prefix"]):
            return imp["project_id"], imp["environment_id"]
    return None


def keyorix_allows(model, op, mount, name):
    scope = keyorix_scope(model, mount, name)
    if scope is None:
        return False
    proj, env = scope
    perm = KEYORIX_PERM[op]
    return any(perm in g["permissions"] and g["project_id"] == proj
               and g["environment_id"] in (0, env) for g in model["grants"])


# ---------------------------------------------------------------- SMT-LIB emission

SEG = '(re.diff re.allchar (str.to_re "/"))'
PRINTABLE_SEG = '(re.union (re.range "a" "z") (re.range "0" "9") (str.to_re "-"))'


def smt_str(s):
    out = []
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('""')
        elif 0x20 <= o < 0x7F and ch != "\\":
            out.append(ch)
        else:
            out.append("\\u{%x}" % o)
    return '"' + "".join(out) + '"'


def smt_unstr(s):
    s = s[1:-1].replace('""', '"')
    return re.sub(r"\\u\{([0-9a-fA-F]+)\}", lambda m: chr(int(m.group(1), 16)), s)


def smt_regex(pattern):
    segs = _segments(pattern)
    parts = []
    lit = ""
    for i, s in enumerate(segs):
        last = i == len(segs) - 1
        sep = "" if last else "/"
        if s == "+":
            if lit:
                parts.append("(str.to_re %s)" % smt_str(lit))
                lit = ""
            parts.append("(re.* %s)" % SEG)
            lit = sep
        elif last and s.endswith("*"):
            lit += s[:-1]
            if lit:
                parts.append("(str.to_re %s)" % smt_str(lit))
            lit = ""
            parts.append("re.all")
        else:
            lit += s + sep
    if lit:
        parts.append("(str.to_re %s)" % smt_str(lit))
    if not parts:
        return '(str.to_re "")'
    return parts[0] if len(parts) == 1 else "(re.++ %s)" % " ".join(parts)


def cap_id(cap):
    return CAPS.index(cap)


def smt_vault_allow(acl, p, cap):
    """ite-chain deciding Vault's verdict for path term p and capability term cap."""
    exact, wild = ordered_rules(acl)

    def verdict(r):
        if "deny" in r["caps"]:
            return "false"
        ids = ["(= %s %d)" % (cap, cap_id(c)) for c in sorted(r["caps"]) if c in CAPS]
        if not ids:
            return "false"
        return ids[0] if len(ids) == 1 else "(or %s)" % " ".join(ids)

    chain = []
    for r in exact:
        chain.append(("(= %s %s)" % (p, smt_str(r["path"])), verdict(r)))
    for r in exact:
        chain.append(("(and (= %s %d) (= %s %s))" % (cap, cap_id("list"), p, smt_str(r["path"] + "/")),
                      verdict(r)))
    for r in wild:
        chain.append(("(str.in_re %s %s)" % (p, smt_regex(r["path"])), verdict(r)))
    expr = "false"
    for cond, val in reversed(chain):
        expr = "(ite %s %s %s)" % (cond, val, expr)
    return expr


def _or(xs):
    xs = list(xs)
    if not xs:
        return "false"
    return xs[0] if len(xs) == 1 else "(or %s)" % " ".join(xs)


def emit_case(model, pretty=False, exclude_ops=()):
    """SMT-LIB 2.6 text for: Keyorix allows and Vault denies (QF_SLIA)."""
    mounts = model["kv_mounts"]
    acl = merge_rules(model["vault_rules"])
    L = ["(set-logic QF_SLIA)", "(set-option :produce-models true)",
         "(declare-const op Int)", "(declare-const mi Int)",
         "(declare-const d String)", "(declare-const leaf String)",
         "(assert (and (<= 0 op) (< op %d)))" % len(OPS),
         "(assert (and (<= 0 mi) (< mi %d)))" % len(mounts)]
    seg = PRINTABLE_SEG if pretty else SEG
    L.append('(assert (str.in_re d (re.* (re.++ (re.+ %s) (str.to_re "/")))))' % seg)
    L.append("(assert (str.in_re leaf (re.+ %s)))" % seg)
    if pretty:
        # Readability only (a second query after a SAT verdict): a leaf that looks like a name.
        L.append('(assert (str.in_re leaf (re.++ (re.range "a" "z") ((_ re.loop 2 12) %s))))' % seg)
    L.append("(define-fun n () String (str.++ d leaf))")
    for o in exclude_ops:
        L.append("(assert (not (= op %d)))" % OPS.index(o))

    # Vault request path per (mount, op).
    path_expr = '""'
    for i in reversed(range(len(mounts))):
        m = mounts[i]
        M = smt_str(m["Path"] if "Path" in m else m["path"])
        ver = m.get("KVVersion", m.get("kv_version"))
        if ver == 2:
            data = "(str.++ %s \"data/\" n)" % M
            per_op = {"read": data, "list": "(str.++ %s \"metadata/\" d)" % M,
                      "read_metadata": "(str.++ %s \"metadata/\" n)" % M,
                      "create": data, "update": data, "delete": data}
        else:
            per_op = {o: "(str.++ %s n)" % M for o in OPS}
            per_op["list"] = "(str.++ %s d)" % M
            L.append("(assert (not (and (= mi %d) (= op %d))))" % (i, OPS.index("read_metadata")))
        e = '""'
        for o in reversed(OPS):
            e = "(ite (= op %d) %s %s)" % (OPS.index(o), per_op[o], e)
        path_expr = "(ite (= mi %d) %s %s)" % (i, e, path_expr)
    L.append("(define-fun p () String %s)" % path_expr)
    cap_expr = "0"
    for o in reversed(OPS):
        cap_expr = "(ite (= op %d) %d %s)" % (OPS.index(o), cap_id(OP_CAP[o]), cap_expr)
    L.append("(define-fun cap () Int %s)" % cap_expr)
    L.append("(define-fun vault_allow () Bool %s)" % smt_vault_allow(acl, "p", "cap"))

    # Keyorix: import scope of the secret, then grant coverage.
    mount_idx = {(m.get("Path") or m.get("path")): i for i, m in enumerate(mounts)}
    sp, se, imported = "0", "0", []
    for imp in reversed(_sorted_imports(model)):
        # A prefix ending in "/" is a prefix of n = d ++ leaf iff it is a prefix of d (leaf
        # holds no "/"). Stating it on d is equivalent and spares z3 that inference: without
        # it, the UNSAT "list" query of constructed-metadata-list-only timed out at 300 s.
        pre = imp["path_prefix"]
        on = "d" if pre == "" or pre.endswith("/") else "n"
        cond = "(and (= mi %d) (str.prefixof %s %s))" % (mount_idx[imp["mount"]], smt_str(pre), on)
        sp = "(ite %s %d %s)" % (cond, imp["project_id"], sp)
        se = "(ite %s %d %s)" % (cond, imp["environment_id"], se)
        imported.append(cond)
    L.append("(define-fun scope_p () Int %s)" % sp)
    L.append("(define-fun scope_e () Int %s)" % se)
    L.append("(define-fun imported () Bool %s)" % _or(imported))
    covers = []
    for g in model["grants"]:
        ops = [o for o in OPS if KEYORIX_PERM[o] in g["permissions"]]
        if not ops:
            continue
        env = "true" if g["environment_id"] == 0 else "(= scope_e %d)" % g["environment_id"]
        covers.append("(and %s (= scope_p %d) %s)" % (_or("(= op %d)" % OPS.index(o) for o in ops),
                                                     g["project_id"], env))
    L.append("(define-fun keyorix_allow () Bool (and imported %s))" % _or(covers))
    L.append("(assert keyorix_allow)")
    L.append("(assert (not vault_allow))")
    L.append("(check-sat)")
    L.append("(get-value (op mi d leaf))")
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------- solver

class SolverError(RuntimeError):
    pass


def run_solver(smt, timeout_s=300, solver="z3"):
    """Run the SMT-LIB text; return (status, {var: value-text}, wall seconds)."""
    if solver == "z3":
        cmd = ["z3", "-in", "-T:%d" % timeout_s]
    elif solver == "cvc5":
        cmd = ["cvc5", "--lang=smt2", "--strings-exp", "--tlimit=%d" % (timeout_s * 1000)]
    else:
        raise SolverError("unknown solver " + solver)
    if shutil.which(cmd[0]) is None:
        raise SolverError("%s not on PATH" % cmd[0])
    t0 = time.perf_counter()
    proc = subprocess.run(cmd, input=smt, capture_output=True, text=True, check=False)  # noqa: S603
    wall = time.perf_counter() - t0
    out = proc.stdout.strip().splitlines()
    status = out[0].strip() if out else "error"
    if status == "timeout" or (status == "unknown"):
        return "unknown", {}, wall
    if status not in ("sat", "unsat"):
        raise SolverError("solver said %r (stderr %r)" % (proc.stdout[:400], proc.stderr[:400]))
    values = {}
    if status == "sat":
        for m in re.finditer(r'\((\w+) ("(?:[^"]|"")*"|-?\d+|\(- \d+\))\)', proc.stdout):
            values[m.group(1)] = m.group(2)
    return status, values, wall


def smt_vault_allows(acl, path, cap):
    """The encoding's verdict on one concrete request (for differential testing)."""
    smt = "\n".join([
        "(set-logic QF_SLIA)",
        "(define-fun p () String %s)" % smt_str(path),
        "(define-fun cap () Int %d)" % cap_id(cap),
        "(assert %s)" % smt_vault_allow(acl, "p", "cap"),
        "(check-sat)"]) + "\n"
    status, _, _ = run_solver(smt, timeout_s=30)
    if status == "unknown":
        raise SolverError("unknown on concrete query")
    return status == "sat"


class CaseResult:
    def __init__(self, name):
        self.name = name
        self.verdict = None
        self.vacuous = False
        self.counterexamples = []
        self.first_query_s = 0.0
        self.total_s = 0.0
        self.queries = 0
        self.smt_bytes = 0
        self.unknown_parts = []  # (mount, op, import prefix) the solver did not decide


def _decode(model, values):
    op = OPS[int(values["op"])]
    mount = model["kv_mounts"][int(values["mi"])]
    mpath = mount.get("Path") or mount.get("path")
    ver = mount.get("KVVersion", mount.get("kv_version"))
    name = smt_unstr(values["d"]) + smt_unstr(values["leaf"])
    path, cap = vault_request(ver, mpath, op, name)
    return {"op": op, "mount": mpath, "name": name, "vault_path": path, "capability": cap,
            "keyorix_scope": keyorix_scope(model, mpath, name),
            "keyorix_permission": KEYORIX_PERM[op]}


def check_case_monolithic(model, timeout_s=300, enumerate_ops=True, solver="z3"):
    """One query over every (mount, op, name); kept as the measured baseline.

    It degrades fast: a subset proof over 30 rules took minutes (see scale.py)."""
    res = CaseResult(model.get("case", "?"))
    res.vacuous = len(model["grants"]) == 0
    excluded = []
    while True:
        smt = emit_case(model, exclude_ops=excluded)
        if res.queries == 0:
            res.smt_bytes = len(smt)
        status, values, wall = run_solver(smt, timeout_s, solver)
        res.queries += 1
        res.total_s += wall
        if res.queries == 1:
            res.first_query_s = wall
        if status == "unknown":
            res.verdict = "unknown" if not res.counterexamples else "widens"
            return res
        if status == "unsat":
            if res.verdict is None:
                res.verdict = "subset"
            return res
        res.verdict = "widens"
        # Prefer a readable witness for the same op; fall back to the raw model.
        op = OPS[int(values["op"])]
        others = [o for o in OPS if o != op]
        st2, v2, w2 = run_solver(emit_case(model, pretty=True, exclude_ops=others), timeout_s, solver)
        res.total_s += w2
        res.queries += 1
        res.counterexamples.append(_decode(model, v2 if st2 == "sat" else values))
        excluded.append(op)
        if not enumerate_ops:
            return res


# ---------------------------------------------------------------- split encoding

def _mount_fields(m):
    return (m.get("Path") or m.get("path")), m.get("KVVersion", m.get("kv_version"))


def _literal_head(pattern):
    """The pattern text before its first wildcard (all of it for an exact rule)."""
    return pattern[:first_wildcard(pattern)]


def _compatible(a, b):
    return a.startswith(b) or b.startswith(a)


def _keyorix_allows_in_scope(model, op, proj, env):
    perm = KEYORIX_PERM[op]
    return any(perm in g["permissions"] and g["project_id"] == proj
               and g["environment_id"] in (0, env) for g in model["grants"])


def emit_part(model, mi, op, imp, pretty=False):
    """SMT-LIB for one part of the question: names of one mount imported by ONE import
    run, one logical op. Returns None when Keyorix does not allow op in that scope (the
    part is then trivially UNSAT and needs no query).

    Why the split is exact, not an approximation: the import that owns a name is
    unique (longest matching prefix, the same rule keyorix_scope applies; longer
    imports are excluded explicitly), so the parts partition the name space, and
    inside one part the Keyorix verdict is a constant. Rules whose literal head cannot
    be prefix-compatible with the part's literal path head never match any path of the
    part, so dropping them from the ite-chain does not change which rule is selected."""
    mpath, ver = _mount_fields(model["kv_mounts"][mi])
    if imp["mount"] != mpath or (ver == 1 and op == "read_metadata"):
        return None
    if not _keyorix_allows_in_scope(model, op, imp["project_id"], imp["environment_id"]):
        return None
    pre = imp["path_prefix"]
    dir_prefix = pre == "" or pre.endswith("/")
    seg = PRINTABLE_SEG if pretty else SEG
    L = ["(set-logic QF_SLIA)", "(set-option :produce-models true)",
         "(declare-const dr String)", "(declare-const leaf String)",
         '(assert (str.in_re dr (re.* (re.++ (re.+ %s) (str.to_re "/")))))' % seg,
         "(assert (str.in_re leaf (re.+ %s)))" % seg]
    if pretty:
        L.append('(assert (str.in_re leaf (re.++ (re.range "a" "z") ((_ re.loop 2 12) %s))))' % seg)
    if dir_prefix:
        L.append("(define-fun d () String (str.++ %s dr))" % smt_str(pre))
        head_name = pre
    else:
        L.append("(define-fun d () String dr)")
        head_name = ""
    L.append("(define-fun n () String (str.++ d leaf))")
    if not dir_prefix:
        L.append("(assert (str.prefixof %s n))" % smt_str(pre))
    for other in model["imports"]:
        op_pre = other["path_prefix"]
        if other["mount"] == mpath and len(op_pre) > len(pre) and op_pre.startswith(pre):
            L.append("(assert (not (str.prefixof %s n)))" % smt_str(op_pre))
    M = smt_str(mpath)
    if ver == 2:
        area = "metadata/" if op in ("list", "read_metadata") else "data/"
        tail = "d" if op == "list" else "n"
        L.append('(define-fun p () String (str.++ %s "%s" %s))' % (M, area, tail))
        head = mpath + area + head_name
    else:
        L.append("(define-fun p () String (str.++ %s %s))" % (M, "d" if op == "list" else "n"))
        head = mpath + head_name
    L.append("(define-fun cap () Int %d)" % cap_id(OP_CAP[op]))
    acl = [r for r in merge_rules(model["vault_rules"])
           if _compatible(_literal_head(r["path"]), head)
           or (op == "list" and is_exact(r["path"]) and _compatible(r["path"] + "/", head))]
    L.append("(assert (not %s))" % smt_vault_allow(acl, "p", "cap"))
    L.append("(check-sat)")
    L.append("(get-value (d leaf))")
    return "\n".join(L) + "\n", len(acl)


def check_case_split(model, timeout_s=300, enumerate_ops=True, solver="z3"):
    res = CaseResult(model.get("case", "?"))
    res.vacuous = len(model["grants"]) == 0
    res.max_part_s = 0.0
    res.max_part_rules = 0
    found = set()
    unknown = False
    for mi in range(len(model["kv_mounts"])):
        mpath, ver = _mount_fields(model["kv_mounts"][mi])
        for op in OPS:
            for imp in model["imports"]:
                if op in found:
                    break
                part = emit_part(model, mi, op, imp)
                if part is None:
                    continue
                smt, nrules = part
                res.smt_bytes += len(smt)
                status, values, wall = run_solver(smt, timeout_s, solver)
                res.queries += 1
                res.total_s += wall
                res.max_part_s = max(res.max_part_s, wall)
                res.max_part_rules = max(res.max_part_rules, nrules)
                if status == "unknown":
                    unknown = True
                    res.unknown_parts.append((mpath, op, imp["path_prefix"]))
                    continue
                if status == "unsat":
                    continue
                if res.verdict is None:
                    res.first_query_s = res.total_s  # time to the first widening found
                res.verdict = "widens"
                st2, v2, w2 = run_solver(emit_part(model, mi, op, imp, pretty=True)[0], timeout_s, solver)
                res.total_s += w2
                res.queries += 1
                vals = v2 if st2 == "sat" else values
                name = smt_unstr(vals["d"]) + smt_unstr(vals["leaf"])
                path, cap = vault_request(ver, mpath, op, name)
                res.counterexamples.append({
                    "op": op, "mount": mpath, "name": name, "vault_path": path, "capability": cap,
                    "keyorix_scope": keyorix_scope(model, mpath, name),
                    "keyorix_permission": KEYORIX_PERM[op]})
                found.add(op)
                if not enumerate_ops:
                    return res
    if res.verdict is None:
        res.verdict = "unknown" if unknown else "subset"
        res.first_query_s = res.total_s
    return res


def check_case(model, timeout_s=300, enumerate_ops=True, solver="z3", mode="split"):
    """Verdict plus one counterexample per widened logical operation."""
    if mode == "monolithic":
        return check_case_monolithic(model, timeout_s, enumerate_ops, solver)
    return check_case_split(model, timeout_s, enumerate_ops, solver)


def load(path):
    with open(path) as f:
        return json.load(f)


def explain(cx):
    scope = cx["keyorix_scope"]
    env = "environment %d" % scope[1]
    return ("%s %r: Vault denies %s on %s; Keyorix allows it via %s on project %d, %s"
            % (cx["op"], cx["name"], cx["capability"], cx["vault_path"],
               cx["keyorix_permission"], scope[0], env))
