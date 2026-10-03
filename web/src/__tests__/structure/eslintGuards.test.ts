// Calibration for the INV-WEB-01 lint guard (eslint.config.mjs, #2528): every shape the
// rule claims to recognise must still be reported, and the shapes it deliberately allows
// must still pass. Runs the repo's real ESLint config via the Node API on in-memory
// snippets, so a config edit that silently stops the rule firing (a typo'd selector, an
// over-broad `ignores`, a rule turned off) fails here instead of passing lint forever.
import { resolve } from 'node:path';
import { ESLint } from 'eslint';
import { describe, expect, it } from 'vitest';

const webRoot = resolve(import.meta.dirname, '../../..');
const eslint = new ESLint({ cwd: webRoot });

async function invWeb01Messages(code: string, filePath: string): Promise<string[]> {
    const [result] = await eslint.lintText(code, { filePath: resolve(webRoot, filePath) });
    return (result?.messages ?? [])
        .filter((m) => m.ruleId === 'no-restricted-syntax' || m.ruleId === 'no-restricted-imports')
        .map((m) => m.message);
}

const PAGE = 'src/pages/secrets/__calibration__.tsx';

const mustFire: Array<[string, string]> = [
    ['bare fetch', `export const f = () => fetch('/api/v1/secrets', { method: 'DELETE' });`],
    ['window.fetch', `export const f = () => window.fetch('/api/v1/secrets');`],
    ['globalThis.fetch', `export const f = () => globalThis.fetch('/api/v1/secrets');`],
    ['XMLHttpRequest', `export const x = new XMLHttpRequest();`],
    ['WebSocket', `export const w = new WebSocket('wss://x');`],
    ['EventSource', `export const e = new EventSource('/events');`],
    ['sendBeacon', `export const b = () => navigator.sendBeacon('/x', '');`],
    ['axios default import', `import axios from 'axios';\nexport const p = () => axios.post('/api/v1/secrets', {});`],
    ['aliased axios default import', `import ax from 'axios';\nexport const c = ax.create();`],
    ['axios namespace import', `import * as ax from 'axios';\nexport const c = ax.default.create();`],
    ['axios default via named', `import { default as ax } from 'axios';\nexport const c = ax.create();`],
    ['axios subpath', `import x from 'axios/unsafe/adapters/xhr.js';\nexport const y = x;`],
    ['dynamic axios import', `export const f = async () => (await import('axios')).default.get('/x');`],
    ['re-export axios', `export { default } from 'axios';`],
    ['re-export all axios', `export * from 'axios';`],
];

const mustPass: Array<[string, string, string]> = [
    [
        'isAxiosError import',
        PAGE,
        `import { isAxiosError } from 'axios';\nexport const f = (e: unknown) => isAxiosError(e);`,
    ],
    ['axios type import', PAGE, `import type { AxiosResponse } from 'axios';\nexport type R = AxiosResponse;`],
    [
        'apiClient call',
        PAGE,
        `import { apiClient } from '@/services/client';\nexport const f = () => apiClient.get('/x');`,
    ],
    ['React Query refetch', PAGE, `export const f = (q: { refetch: () => void }) => q.refetch();`],
    ['allowlisted client.ts', 'src/services/client.ts', `import axios from 'axios';\nexport const c = axios.create();`],
    ['allowlisted auth.ts', 'src/services/auth.ts', `import axios from 'axios';\nexport const c = axios.create();`],
    ['allowlisted setup.ts', 'src/services/setup.ts', `import axios from 'axios';\nexport const c = axios.create();`],
];

describe('INV-WEB-01 lint guard: no raw HTTP outside the reviewed axios instances', () => {
    it.each(mustFire)('reports %s in a page', async (_name, code) => {
        expect(await invWeb01Messages(code, PAGE)).not.toEqual([]);
    });

    it.each(mustFire)('reports %s in a non-allowlisted service', async (_name, code) => {
        expect(await invWeb01Messages(code, 'src/services/__calibration__.ts')).not.toEqual([]);
    });

    it.each(mustPass)('allows %s', async (_name, filePath, code) => {
        expect(await invWeb01Messages(code, filePath)).toEqual([]);
    });
});
