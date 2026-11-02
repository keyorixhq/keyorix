#!/usr/bin/env node
// Advisory check: lists every double-quoted phrase in the two secret-sharing guides
// (outside code fences) that does not appear in the web/src sources (components, pages,
// constants; test files excluded). The web UI keeps its strings inline (there is no i18n
// layer), so a plain substring search over the source is the whole check.
//
// Advisory on purpose: quoted phrases also name CLI output, server error text and
// labels built at runtime (for example "Read + update value/metadata, rotate"), so a hit is
// a prompt to look, not proof of a stale claim. It prints a list and exits 0; pass
// --strict to exit 1 when anything is listed. Not wired into CI.
//
// Usage: node scripts/check-sharing-guide-ui-strings.mjs [--strict]

import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const webDir = join(dirname(fileURLToPath(import.meta.url)), '..');
const repoDir = join(webDir, '..');
const GUIDES = ['docs/SECRET_SHARING_USER_GUIDE.md', 'docs/SECRET_SHARING_WORKFLOWS.md'];
const strict = process.argv.includes('--strict');

const isTest = (p) => /\.test\.tsx?$/.test(p) || p.includes('/__tests__/') || p.includes('/test/');

function sources(dir, out = []) {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
        const p = join(dir, e.name);
        if (e.isDirectory()) sources(p, out);
        else if (/\.(tsx?|json)$/.test(e.name) && !isTest(p) && !p.endsWith('api-generated.ts')) out.push(p);
    }
    return out;
}

const haystack = sources(join(webDir, 'src'))
    .map((p) => readFileSync(p, 'utf8'))
    .join('\n');

// Ellipsis and quote variants differ between prose and source.
const norm = (s) => s.replace(/…/g, '...').replace(/[‘’]/g, "'").replace(/\s+/g, ' ').trim();
const normHay = norm(haystack);

// A phrase is worth checking when it reads like a label: starts with a letter, 2-60
// chars, and is not a placeholder or a data example (<...>, $VAR, key: value).
const looksLikeLabel = (s) => /^[A-Za-z][^<>${}]{1,59}$/.test(s) && !/[:=]\s/.test(s);

const findings = [];
for (const rel of GUIDES) {
    let fenced = false;
    readFileSync(join(repoDir, rel), 'utf8')
        .split('\n')
        .forEach((line, i) => {
            if (/^\s*```/.test(line)) {
                fenced = !fenced;
                return;
            }
            if (fenced) return;
            for (const m of line.matchAll(/"([^"]+)"/g)) {
                const phrase = m[1];
                if (!looksLikeLabel(phrase)) continue;
                if (!normHay.includes(norm(phrase)))
                    findings.push(`${relative(repoDir, join(repoDir, rel))}:${i + 1}: "${phrase}"`);
            }
        });
}

if (findings.length === 0) {
    console.log('check-sharing-guide-ui-strings: every quoted UI string in the sharing guides is present in web/src.');
} else {
    console.log(
        `check-sharing-guide-ui-strings: ${findings.length} quoted string(s) not found in web/src (advisory; may be CLI/server text or built at runtime):`
    );
    for (const f of findings) console.log('  ' + f);
}
process.exit(strict && findings.length > 0 ? 1 : 0);
