// Extracts the audit event types the server can emit, by reading the Go sources
// as text (no Go build). Used by src/utils/__tests__/eventLabelsParity.test.ts to
// fail when an emitted event has neither a label in src/utils/eventLabels.ts nor
// an entry (with a reason) in audit-intentionally-unlabelled.mjs.
//
// There is no single declaration site: event types are declared as constants
// spread over internal/core, server/admin and other packages, and many emitters
// pass a string literal or a constant straight to a write helper. So the
// extractor recognises exactly these forms in non-test Go files under internal/
// and server/, after stripping // and /* */ comments:
//   1. a declaration whose name contains "event" or "Event" (any case, any
//      position: EventFoo, eventAdminResetMFA, auditSealEvent, eventType) set to
//      a literal:  name = "area.name" / name := "area.name" / name T = "area.name"
//      Names starting with "Notification" are skipped (notification kinds, not
//      audit rows).
//   2. a struct field  EventType: "area.name"  or  EventType: someIdent
//   3. an argument of a writer call: a call whose name contains "audit" or
//      "Audit" (writeAuditEventFull, auditProjectScopedOn, ...), or one of the
//      named writers whose names lack it: recordAdminAction (server/admin),
//      setAccountState*, logMachineEvent*, logMachineCascadeEvent and
//      logMembershipEvent (internal/core; each forwards its event argument to
//      writeAuditEvent*). The first string
//      literal among its arguments counts when it is not the first argument
//      (the first is ctx/cfg); every identifier before that literal counts too.
// An identifier (form 2 or 3) is resolved against every `ident = "area.name"`
// assignment in the same Go package (directory). A literal prefix ending in "."
// or "_" followed by `+ ident` ("admin.recovery_key."+action) in forms 1-3 is
// expanded with every `ident = "word"` assignment in the same file.
// Only strings shaped like "area.name" (lower-case, one or more dots) count.
//
// What it does NOT see:
//   - event types assembled at run time other than the prefix + ident form
//     above: fmt.Sprintf, prefix + function call ("membership."+transitionVerb(to)),
//     a type chosen from a map;
//   - a constant declared in another package whose name lacks "event"/"Event"
//     and is passed qualified (pkg.SomeName) to a writer;
//   - a literal passed to a writer outside form 3: a new wrapper that forwards
//     its event argument to writeAuditEvent* is invisible until its name is
//     added to WRITER_CALL;
//   - a literal after a ")" inside the writer's argument list (the argument scan
//     stops at the first ")" or string literal).
// So the check proves "no event emitted in a recognised form is unlabelled",
// not "every event is labelled". Over-matching (a non-audit string that looks
// like "area.name") fails safe: it needs a label or a ledger entry, it never
// hides an event.

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = resolve(HERE, '..', '..');
export const SCAN_ROOTS = ['internal', 'server'];

// All patterns are literals (no RegExp built from data). A "literal" capture
// accepts an event shape or a prefix ending in "." / "_"; isEvent/isPrefix sort
// them out afterwards.
const SHAPE = /^[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+$/;
const PREFIX = /^[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)*[._]$/;
const DECLARATION = /\b(\w*[Ee]vent\w*)(?:\s+[\w.]+)?\s*:?=\s*"([a-z][a-z0-9_.]*)"(?:\s*\+\s*(\w+))?/g;
const STRUCT_FIELD = /\bEventType:\s*(?:"([a-z][a-z0-9_.]*)"(?:\s*\+\s*(\w+))?|([A-Za-z_]\w*))/g;
const WRITER_CALL =
    /\b(?:\w*[Aa]udit\w*|recordAdminAction|setAccountState\w*|logMachineEvent\w*|logMachineCascadeEvent|logMembershipEvent)\(([^")]*)(?:"([a-z][a-z0-9_.]*)"(?:\s*\+\s*(\w+))?)?/g;
const IDENT = /\b[A-Za-z_]\w*\b/g;
const SHAPED_ASSIGN = /\b([A-Za-z_]\w*)(?:\s+[\w.]+)?\s*:?=\s*"([a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+)"/g;
const WORD_ASSIGN = /\b(\w+)\s*:?=\s*"([a-z0-9_]+)"/g;
const BLOCK_COMMENT = /(^|\s)\/\*[\s\S]*?\*\//g;
const LINE_COMMENT = /(^|\s)\/\/.*$/gm;

const SKIP_DIRS = new Set(['node_modules', 'testdata', 'vendor', '.git']);

function* goFiles(dir) {
    for (const name of readdirSync(dir)) {
        if (SKIP_DIRS.has(name)) continue;
        const full = join(dir, name);
        const st = statSync(full);
        if (st.isDirectory()) yield* goFiles(full);
        else if (name.endsWith('.go') && !name.endsWith('_test.go')) yield full;
    }
}

/** Strip comments so a commented-out example never counts as an emitter. */
function stripComments(src) {
    return src.replace(BLOCK_COMMENT, '$1').replace(LINE_COMMENT, '$1');
}

function addTo(map, key, value) {
    if (!map.has(key)) map.set(key, new Set());
    map.get(key).add(value);
}

/** Pure: identifier -> event-shaped string literals assigned to it in one Go source. */
export function extractDeclarations(src) {
    const out = new Map();
    for (const m of stripComments(src).matchAll(SHAPED_ASSIGN)) addTo(out, m[1], m[2]);
    return out;
}

/**
 * Pure: event types found in one Go source text. `decls` maps an identifier to
 * the event string(s) it may hold (normally the whole package's
 * extractDeclarations); identifier arguments are resolved through it.
 */
export function extractFromSource(src, decls = new Map()) {
    const text = stripComments(src);
    const found = new Set();
    const prefixes = [];
    const literal = (lit, concatVar) => {
        if (!lit) return;
        if (concatVar && PREFIX.test(lit)) prefixes.push([lit, concatVar]);
        else if (SHAPE.test(lit)) found.add(lit);
    };
    const ident = (name) => {
        const values = decls.get(name);
        if (values === undefined) return;
        for (const v of typeof values === 'string' ? [values] : values) if (SHAPE.test(v)) found.add(v);
    };

    for (const m of text.matchAll(DECLARATION)) {
        if (!m[1].startsWith('Notification')) literal(m[2], m[3]);
    }
    for (const m of text.matchAll(STRUCT_FIELD)) {
        literal(m[1], m[2]);
        if (m[3]) ident(m[3]);
    }
    for (const m of text.matchAll(WRITER_CALL)) {
        const args = m[1];
        // The first argument is ctx/cfg: a literal counts only after a comma.
        if (/,\s*$/.test(args)) literal(m[2], m[3]);
        for (const id of args.matchAll(IDENT)) ident(id[0]);
    }

    // "area.name_" + state: replace the prefix by prefix + every word literal
    // assigned to that variable in the same file (state := "enabled" /
    // state = "disabled"). Over-generates when the name is reused; fails safe.
    if (prefixes.length > 0) {
        const words = new Map();
        for (const m of text.matchAll(WORD_ASSIGN)) addTo(words, m[1], m[2]);
        for (const [prefix, v] of prefixes) {
            for (const w of words.get(v) ?? []) if (SHAPE.test(prefix + w)) found.add(prefix + w);
        }
    }
    return found;
}

/** Map of event type -> sorted list of repo-relative files that declare/emit it. */
export function extractEmittedActions(repoRoot = REPO_ROOT) {
    // Group by directory: Go constants are package-scoped, so an identifier
    // argument resolves against declarations anywhere in its package.
    const packages = new Map();
    for (const root of SCAN_ROOTS) {
        for (const file of goFiles(join(repoRoot, root))) {
            const dir = dirname(file);
            if (!packages.has(dir)) packages.set(dir, []);
            packages.get(dir).push([file, readFileSync(file, 'utf8')]);
        }
    }
    const out = new Map();
    for (const files of packages.values()) {
        const decls = new Map();
        for (const [, src] of files) {
            for (const [k, vs] of extractDeclarations(src)) for (const v of vs) addTo(decls, k, v);
        }
        for (const [file, src] of files) {
            const rel = file.slice(repoRoot.length + 1);
            for (const action of extractFromSource(src, decls)) addTo(out, action, rel);
        }
    }
    return new Map([...out.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => [k, [...v].sort()]));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
    const actions = extractEmittedActions();
    for (const [action, files] of actions) console.log(`${action}\t${files.join(',')}`);
    console.error(`audit-actions: ${actions.size} emitted event types`);
}
