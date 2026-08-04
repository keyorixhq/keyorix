#!/usr/bin/env node
/**
 * Generates a production-only CycloneDX SBOM for web/, for embedding
 * coverage of the dashboard baked into keyorix-server via go:embed
 * (ADR-073). Usage: node scripts/build-frontend-sbom.mjs <output-file>
 *
 * Two tools, two failure modes ADR-073 measured against the real files:
 *   - cdxgen must run with NO --type flag. `--type npm` silently drops to
 *     scanning package.json's direct dependencies only (47 components) —
 *     no error, just wrong. Autodetection correctly parses pnpm-lock.yaml
 *     for full transitive resolution (478 components, matching `pnpm list`
 *     exactly).
 *   - cdxgen's own --required-only / scope inference is not production-
 *     accurate for this project (it included eslint and eslint plugins in
 *     a real test run). Production scope is derived here from
 *     `pnpm list --prod`, not from cdxgen's own classification.
 *
 * Filtering the component list alone leaves the `dependencies` graph
 * referencing removed components — schema-valid but semantically broken
 * (471 dangling `dependsOn` entries in ADR-073's own test). This script
 * prunes both.
 */

import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const outputFile = process.argv[2];
if (!outputFile) {
    console.error('[frontend-sbom] usage: build-frontend-sbom.mjs <output-file>');
    process.exit(1);
}

function fail(message) {
    console.error(`[frontend-sbom] FAIL: ${message}`);
    process.exit(1);
}

// 1. Full transitive SBOM via cdxgen, autodetected (no --type — see header).
const rawSbomFile = join(tmpdir(), `cdxgen-raw-${process.pid}.json`);
try {
    execFileSync(
        'cdxgen',
        ['--spec-version', '1.6', '--output', rawSbomFile, '.'],
        { stdio: ['ignore', 'ignore', 'inherit'] },
    );
} catch (err) {
    fail(`cdxgen invocation failed: ${err.message}`);
}

let bom;
try {
    bom = JSON.parse(readFileSync(rawSbomFile, 'utf8'));
} catch (err) {
    fail(`could not parse cdxgen output: ${err.message}`);
} finally {
    try {
        unlinkSync(rawSbomFile);
    } catch {
        // best-effort cleanup
    }
}

if (bom.bomFormat !== 'CycloneDX' || bom.specVersion !== '1.6') {
    fail(`cdxgen produced unexpected bomFormat/specVersion: ${bom.bomFormat} ${bom.specVersion}`);
}

// 2. Production-only package set, ground truth from pnpm itself.
let prodTree;
try {
    const raw = execFileSync('pnpm', ['list', '--prod', '--depth', 'Infinity', '--json'], {
        encoding: 'utf8',
    });
    prodTree = JSON.parse(raw);
} catch (err) {
    fail(`\`pnpm list --prod --depth Infinity --json\` failed: ${err.message}`);
}

const prodKeys = new Set();
function collect(node) {
    for (const key of ['dependencies', 'devDependencies', 'optionalDependencies']) {
        const deps = node[key];
        if (!deps) continue;
        for (const [name, info] of Object.entries(deps)) {
            prodKeys.add(`${name}@${info.version}`);
            collect(info);
        }
    }
}
for (const pkg of prodTree) collect(pkg);

if (prodKeys.size === 0) {
    fail('pnpm reported zero production dependencies — refusing to emit a suspiciously empty SBOM');
}

// 3. Filter components to the production set. Match on group+name+version
//    (purl), not name alone — scoped packages (@radix-ui/*, etc.) report
//    group and name as separate fields, and a name-only match silently
//    drops every scoped production package (73 of 125 in ADR-073's test).
function componentKey(c) {
    const name = c.group ? `${c.group}/${c.name}` : c.name;
    return `${name}@${c.version}`;
}

const allComponents = bom.components ?? [];
const keptRefs = new Set();
const kept = [];
for (const c of allComponents) {
    if (prodKeys.has(componentKey(c))) {
        kept.push(c);
        if (c['bom-ref']) keptRefs.add(c['bom-ref']);
    }
}

// Fail loudly on any mismatch between the two sources of truth, rather than
// silently shipping an under- or over-counted SBOM.
if (kept.length !== prodKeys.size) {
    const keptKeys = new Set(kept.map(componentKey));
    const missing = [...prodKeys].filter(k => !keptKeys.has(k));
    fail(
        `production package count mismatch: pnpm reports ${prodKeys.size}, matched ${kept.length} ` +
            `in cdxgen output. Missing from cdxgen output: ${missing.join(', ') || '(none — duplicate match?)'}`,
    );
}

// 4. Prune the dependency graph too — not just the component list — or
//    every remaining node keeps `dependsOn` entries pointing at removed
//    dev components (471 dangling refs, unpruned, in ADR-073's test).
const rootRef = bom.metadata?.component?.['bom-ref'];
if (rootRef) keptRefs.add(rootRef);

const prunedDependencies = (bom.dependencies ?? [])
    .filter(dep => keptRefs.has(dep.ref))
    .map(dep => ({
        ...dep,
        dependsOn: (dep.dependsOn ?? []).filter(ref => keptRefs.has(ref)),
    }));

bom.components = kept;
bom.dependencies = prunedDependencies;

writeFileSync(outputFile, JSON.stringify(bom, null, 2));
console.log(`[frontend-sbom] wrote ${outputFile}: ${kept.length} production components`);
