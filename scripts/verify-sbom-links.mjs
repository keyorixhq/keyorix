#!/usr/bin/env node
/**
 * Verifies the ADR-073 build-order constraint (decision #5, issue #1792):
 * recomputes the shipped frontend SBOM's SHA-256 from the bytes on disk and
 * asserts it matches the hash embedded in each of the four server Go SBOMs'
 * `bom`-type externalReferences entry.
 *
 * This is deliberately NOT "does the hashes field exist" — that would pass a
 * build-order regression silently (a stale/absent-file hash still populates
 * the field, it's just wrong). Recompute-and-compare is the only check that
 * actually proves the link is trustworthy. See ADR-073 decision #5 and
 * scripts/link-sbom.mjs's own header for why the hash exists at all.
 *
 * Usage: node scripts/verify-sbom-links.mjs <frontend-sbom-file> <server-sbom-file>...
 * Exits non-zero on any failure. Prints one distinct, file-named message per
 * failure and keeps checking the rest rather than stopping at the first.
 */

import { createHash } from 'node:crypto';
import { readFileSync, existsSync } from 'node:fs';

const [frontendSbomFile, ...serverSbomFiles] = process.argv.slice(2);

if (!frontendSbomFile || serverSbomFiles.length === 0) {
    console.error(
        '[verify-sbom-links] usage: verify-sbom-links.mjs <frontend-sbom-file> <server-sbom-file>...',
    );
    process.exit(1);
}

const REQUIRED_LINKED_COUNT = 4;
const errors = [];

if (!existsSync(frontendSbomFile)) {
    console.error(
        `[verify-sbom-links] FAIL: ${frontendSbomFile} does not exist -- cannot verify links ` +
            `against a frontend SBOM that was never generated`,
    );
    process.exit(1);
}

const frontendBytes = readFileSync(frontendSbomFile);
const actualHash = createHash('sha256').update(frontendBytes).digest('hex');

let linkedCount = 0;

for (const serverSbomFile of serverSbomFiles) {
    if (!existsSync(serverSbomFile)) {
        errors.push(`${serverSbomFile}: file does not exist`);
        continue;
    }

    let serverSbom;
    try {
        serverSbom = JSON.parse(readFileSync(serverSbomFile, 'utf8'));
    } catch (err) {
        errors.push(`${serverSbomFile}: could not parse JSON (${err.message})`);
        continue;
    }

    const refs = serverSbom.metadata?.component?.externalReferences ?? [];
    const bomRef = refs.find(r => r.type === 'bom');

    if (!bomRef) {
        errors.push(
            `${serverSbomFile}: no 'bom'-type externalReferences entry -- this SBOM is not ` +
                `linked to the frontend SBOM at all`,
        );
        continue;
    }

    const sha256Entry = (bomRef.hashes ?? []).find(h => h.alg === 'SHA-256');
    if (!sha256Entry || !sha256Entry.content) {
        errors.push(
            `${serverSbomFile}: 'bom' externalReferences entry exists but carries no SHA-256 ` +
                `hash (hashes: ${JSON.stringify(bomRef.hashes ?? [])})`,
        );
        continue;
    }

    if (sha256Entry.content !== actualHash) {
        errors.push(
            `${serverSbomFile}: embedded hash does not match the frontend SBOM's actual ` +
                `SHA-256 -- embedded=${sha256Entry.content} actual=${actualHash} ` +
                `(build-order regression: the frontend SBOM was generated/modified after ` +
                `this link was written)`,
        );
        continue;
    }

    linkedCount++;
}

if (linkedCount < REQUIRED_LINKED_COUNT) {
    errors.push(
        `only ${linkedCount} of ${REQUIRED_LINKED_COUNT} required server SBOMs carry a ` +
            `verified link to the frontend SBOM (checked: ${serverSbomFiles.join(', ')})`,
    );
}

if (errors.length > 0) {
    console.error(`[verify-sbom-links] FAIL (${errors.length} problem(s)):`);
    for (const e of errors) console.error(`  - ${e}`);
    process.exit(1);
}

console.log(
    `[verify-sbom-links] OK: ${linkedCount} server SBOMs correctly linked to ` +
        `${frontendSbomFile} (sha256:${actualHash})`,
);
