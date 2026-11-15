// Extracts the audit event types the server can emit, by reading the Go sources
// as text (no Go build). Used by src/utils/__tests__/eventLabelsParity.test.ts to
// fail when an emitted event has neither a label in src/utils/eventLabels.ts nor
// an entry (with a reason) in audit-intentionally-unlabelled.mjs.
//
// There is no single declaration site: event types are declared as Event*
// constants spread over internal/core (and a few other packages), and many
// emitters pass a string literal straight to a write helper. So the extractor
// recognises exactly these forms in non-test Go files under internal/ and server/:
//   1. a declaration   EventFoo = "area.name"   (const/var, grouped or not)
//   2. a struct field  EventType: "area.name"
//   3. a literal first-after-ctx argument of a call whose name contains
//      "Audit" (writeAuditEvent, writeAuditEventFull, writeAuditEventFailed, ...)
// and only strings shaped like "area.name" (lower-case, one or more dots).
// What it does NOT see: event types assembled at run time (fmt.Sprintf,
// string concatenation, a type chosen from a map), and strings passed through a
// helper whose name lacks "Audit". Such an event is invisible to this check, so
// the check proves "no known literal is unlabelled", not "every event is labelled".

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = resolve(HERE, '..', '..');
export const SCAN_ROOTS = ['internal', 'server'];

const SHAPE = '[a-z][a-z0-9_]*(?:\\.[a-z0-9_]+)+';
const DECLARATION = new RegExp(`\\bEvent\\w+\\s*(?::?=)\\s*"(${SHAPE})"`, 'g');
const STRUCT_FIELD = new RegExp(`\\bEventType:\\s*"(${SHAPE})"`, 'g');
const AUDIT_CALL = new RegExp(`\\w*Audit\\w*\\([^"\\n)]*?,\\s*"(${SHAPE})"`, 'g');

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

/** Strip // line comments so a commented-out example never counts as an emitter. */
function stripLineComments(src) {
    return src
        .split('\n')
        .map((l) => l.replace(/(^|\s)\/\/.*$/, '$1'))
        .join('\n');
}

/** Pure: event types found in one Go source text. */
export function extractFromSource(src) {
    const text = stripLineComments(src);
    const found = new Set();
    for (const re of [DECLARATION, STRUCT_FIELD, AUDIT_CALL]) {
        re.lastIndex = 0;
        for (const m of text.matchAll(re)) found.add(m[1]);
    }
    // "area.name_" + state: a literal ending in "_" is a prefix, not an event.
    // Replace it by prefix + every string literal assigned to that variable in
    // the same file (state := "enabled" / state = "disabled").
    for (const prefix of [...found].filter((a) => a.endsWith('_'))) {
        found.delete(prefix);
        const concat = new RegExp(`"${prefix.replace(/\./g, '\\.')}"\\s*\\+\\s*(\\w+)`, 'g');
        for (const m of text.matchAll(concat)) {
            const assign = new RegExp(`\\b${m[1]}\\s*(?::=|=)\\s*"([a-z0-9_]+)"`, 'g');
            for (const a of text.matchAll(assign)) found.add(prefix + a[1]);
        }
    }
    return found;
}

/** Map of event type -> sorted list of repo-relative files that declare/emit it. */
export function extractEmittedActions(repoRoot = REPO_ROOT) {
    const out = new Map();
    for (const root of SCAN_ROOTS) {
        const dir = join(repoRoot, root);
        for (const file of goFiles(dir)) {
            const rel = file.slice(repoRoot.length + 1);
            for (const action of extractFromSource(readFileSync(file, 'utf8'))) {
                if (!out.has(action)) out.set(action, new Set());
                out.get(action).add(rel);
            }
        }
    }
    return new Map([...out.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => [k, [...v].sort()]));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
    const actions = extractEmittedActions();
    for (const [action, files] of actions) console.log(`${action}\t${files.join(',')}`);
    console.error(`audit-actions: ${actions.size} emitted event types`);
}
