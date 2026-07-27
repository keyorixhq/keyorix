#!/usr/bin/env node
/**
 * Checks that all production dependency licenses are enterprise-safe.
 * Runs `pnpm licenses list --prod --json` internally so no piping is needed
 * from the caller — just `node scripts/license-check.mjs`.
 *
 * Fails on any copyleft license (GPL, AGPL, LGPL, EUPL) that would require
 * open-sourcing Keyorix's product code.  Alert recipients: EU CRA Article 13
 * requires supply-chain transparency; this gate prevents accidental ingestion
 * of license-incompatible code.
 */

import { execSync } from 'child_process';

const ALLOWED = new Set([
    '0BSD',
    'Apache-2.0',
    'Artistic-2.0',
    'BlueOak-1.0.0',
    'BSD-2-Clause',
    'BSD-3-Clause',
    'CC-BY-3.0',
    'CC-BY-4.0',
    'CC0-1.0',
    'ISC',
    'MIT',
    'MPL-2.0',
    'Python-2.0',
    'Unlicense',
    'WTFPL',
]);

let raw;
try {
    raw = execSync('pnpm licenses list --prod --json', { encoding: 'utf8' });
} catch (err) {
    console.error('[license] failed to run `pnpm licenses list --prod --json`:', err.message);
    process.exit(1);
}

let licenses;
try {
    licenses = JSON.parse(raw);
} catch {
    console.error('[license] could not parse pnpm licenses output as JSON');
    process.exit(1);
}

const found = Object.keys(licenses).sort();
const violations = found.filter(l => !ALLOWED.has(l));

console.log('[license] found:', found.join(', ') || '(none)');

if (violations.length > 0) {
    for (const lic of violations) {
        const pkgs = licenses[lic].map(p => `${p.name}@${p.version}`).join(', ');
        console.error(`[license] FAIL — restricted license "${lic}" in: ${pkgs}`);
    }
    process.exit(1);
}

console.log('[license] all production licenses OK');
