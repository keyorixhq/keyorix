#!/usr/bin/env node
// Reads `pnpm audit --json --prod` from stdin, exits 1 if any HIGH/CRITICAL
// advisory is found outside the ignore list.
//
// Usage: pnpm audit --json --prod | node scripts/audit-check.mjs

// No advisories are currently suppressed. If one needs to be, document the
// GHSA id, the vulnerable range, and why it isn't reachable in this app —
// and remove the entry once the lockfile moves past the vulnerable range
// (a suppression for a version this app no longer has installed is dead
// weight that silently stops meaning anything).
const IGNORED = new Set();

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
