#!/usr/bin/env node
// Reads `pnpm audit --json --prod` from stdin, exits 1 if any HIGH/CRITICAL
// advisory is found outside the ignore list.
//
// Usage: pnpm audit --json --prod | node scripts/audit-check.mjs

// GHSA-qwww-vcr4-c8h2: react-router RSC-mode CSRF bypass (>=7.12.0 <8.3.0).
// Patched only in the breaking v8.x line. This app is a SPA; the RSC request
// handler that contains the vulnerability is never loaded or executed.
const IGNORED = new Set(['GHSA-qwww-vcr4-c8h2']);

const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const audit = JSON.parse(Buffer.concat(chunks).toString());

const advisories = Object.values(audit.advisories ?? {});
const failures = advisories.filter(
    a => ['high', 'critical'].includes(a.severity) && !IGNORED.has(a.github_advisory_id),
);
const suppressed = advisories.filter(
    a => ['high', 'critical'].includes(a.severity) && IGNORED.has(a.github_advisory_id),
);

if (suppressed.length > 0) {
    suppressed.forEach(a =>
        console.log(`[audit] suppressed ${a.github_advisory_id} (${a.severity}): ${a.title}`),
    );
}

if (failures.length > 0) {
    failures.forEach(a =>
        console.error(`[audit] FAIL ${a.github_advisory_id} (${a.severity}): ${a.title}`),
    );
    process.exit(1);
}
