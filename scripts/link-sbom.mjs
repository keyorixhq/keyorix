#!/usr/bin/env node
/**
 * Adds a `bom`-type externalReferences entry (with a SHA-256 hash) to a Go
 * SBOM's metadata.component, pointing at the frontend SBOM (ADR-073).
 *
 * Usage: node scripts/link-sbom.mjs <go-sbom-file> <frontend-sbom-file>
 *
 * Build-order constraint (binding, see ADR-073): the frontend SBOM must
 * already exist in its final form when this runs. The hash embedded here
 * is only trustworthy if it describes the file that actually ships —
 * hashing a not-yet-final frontend SBOM produces a reference that
 * validates cleanly while pointing at a stale hash.
 */

import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { basename } from 'node:path';

const [goSbomFile, frontendSbomFile] = process.argv.slice(2);
if (!goSbomFile || !frontendSbomFile) {
    console.error('[link-sbom] usage: link-sbom.mjs <go-sbom-file> <frontend-sbom-file>');
    process.exit(1);
}

function fail(message) {
    console.error(`[link-sbom] FAIL: ${message}`);
    process.exit(1);
}

if (!existsSync(frontendSbomFile)) {
    fail(
        `${frontendSbomFile} does not exist yet — the frontend SBOM must be generated before ` +
            `linking it from any Go SBOM (build-order constraint, ADR-073)`,
    );
}

const frontendBytes = readFileSync(frontendSbomFile);
const hash = createHash('sha256').update(frontendBytes).digest('hex');

let goSbom;
try {
    goSbom = JSON.parse(readFileSync(goSbomFile, 'utf8'));
} catch (err) {
    fail(`could not read/parse ${goSbomFile}: ${err.message}`);
}

if (!goSbom.metadata?.component) {
    fail(`${goSbomFile} has no metadata.component to attach the link to`);
}

const link = {
    type: 'bom',
    url: basename(frontendSbomFile),
    comment:
        'Frontend (web/) production dependency SBOM for the dashboard embedded in this binary ' +
        'via go:embed. See ADR-073.',
    hashes: [{ alg: 'SHA-256', content: hash }],
};

goSbom.metadata.component.externalReferences ??= [];
goSbom.metadata.component.externalReferences.push(link);

writeFileSync(goSbomFile, JSON.stringify(goSbom, null, 2));
console.log(`[link-sbom] linked ${goSbomFile} -> ${basename(frontendSbomFile)} (sha256:${hash})`);
