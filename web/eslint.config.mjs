import { defineConfig } from 'eslint/config';
import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import reactHooks from 'eslint-plugin-react-hooks';
import reactRefresh from 'eslint-plugin-react-refresh';
import noUnsanitized from 'eslint-plugin-no-unsanitized';
import globals from 'globals';

export default defineConfig(
    // Replaces .eslintignore / ignorePatterns. The legacy `eslint . --ext ts,tsx`
    // only linted TS/TSX, so `public/` (e.g. the service worker sw.js) was never
    // linted — keep it that way to avoid spurious no-undef on browser/SW globals.
    {
        ignores: ['dist', 'node_modules', 'public', '**/*.config.ts', '**/*.config.js', '**/*.config.mjs'],
    },

    // Base recommended sets (eslint:recommended + @typescript-eslint/recommended).
    // Scope eslint:recommended to TS/TSX to mirror the old --ext ts,tsx behavior.
    { files: ['**/*.{ts,tsx}'], ...js.configs.recommended },
    ...tseslint.configs.recommended,

    // Catch dangerous DOM sinks (innerHTML, outerHTML, insertAdjacentHTML, etc.)
    // that bypass React's XSS protections.  Scoped to TS/TSX so config files
    // written in plain JS aren't covered by DOM-only rules.
    { files: ['**/*.{ts,tsx}'], ...noUnsanitized.configs.recommended },

    // Restore ESLint 8 behavior: unused eslint-disable directives are a warning,
    // not an error (ESLint 9+ changed the default severity of this flag to error).
    {
        linterOptions: {
            reportUnusedDisableDirectives: 'warn',
        },
    },

    // Project source
    {
        files: ['**/*.{ts,tsx}'],
        languageOptions: {
            ecmaVersion: 'latest',
            sourceType: 'module',
            parserOptions: {
                ecmaFeatures: { jsx: true },
            },
            globals: {
                ...globals.browser,
                ...globals.es2021,
            },
        },
        plugins: {
            'react-hooks': reactHooks,
            'react-refresh': reactRefresh,
        },
        rules: {
            // Turned off until shadcn/ui rewrite — codebase has widespread legitimate any usage
            '@typescript-eslint/no-explicit-any': 'off',
            '@typescript-eslint/no-non-null-assertion': 'off',

            // Real errors
            'no-useless-catch': 'error',
            '@typescript-eslint/no-inferrable-types': 'error',
            '@typescript-eslint/no-empty-function': 'error',

            // Warn on unused vars — prefix with _ to suppress intentionally
            '@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],

            // Console — warn in src, off in tests
            'no-console': ['warn', { allow: ['warn', 'error'] }],

            // react-refresh only applies to component files — suppress for utils/hooks/test files
            'react-refresh/only-export-components': 'off',

            // Keep react-hooks rules on
            'react-hooks/rules-of-hooks': 'error',
            'react-hooks/exhaustive-deps': 'warn',

            // Rules newly added to the recommended sets by the eslint 8->10 /
            // @typescript-eslint 5->8 bump. These weren't enforced before; keep
            // them visible as warnings (not build-failing) so they can be
            // addressed in a dedicated lint-cleanup pass rather than this bump.
            // - no-unused-expressions: flags intentional `cond ? a() : b()` side-effect ternaries
            // - preserve-caught-error: flags re-throwing a new Error without { cause } in catch
            // - no-useless-assignment: flags initializer overwritten in all branches
            '@typescript-eslint/no-unused-expressions': 'warn',
            'preserve-caught-error': 'warn',
            'no-useless-assignment': 'warn',
        },
    },

    // INV-WEB-01 (#2528): every HTTP call in the app goes through one of the reviewed
    // axios instances, which own withCredentials, the CSRF double-submit header, the
    // X-Request-ID, and proactive session refresh:
    //   - services/client.ts  `apiClient` (everything authenticated)
    //   - services/auth.ts    `authApi`   (the auth surface; separate to break the
    //                                      auth -> client -> authStore -> auth cycle)
    //   - services/setup.ts   ADR-028 single-use setup-token flow — deliberately
    //                         unauthenticated: no session cookie, the bearer is the
    //                         token in the URL/body
    // Anywhere else, a raw fetch/XHR/WebSocket/EventSource/sendBeacon or a new axios
    // instance would silently skip all of that. Shapes recognised (each one is
    // exercised by src/__tests__/structure/eslintGuards.test.ts, which fails if it
    // stops firing):
    //   - fetch(...), window/globalThis/self.fetch(...)
    //   - new XMLHttpRequest / WebSocket / EventSource, navigator.sendBeacon(...)
    //   - any axios import other than the allowlisted types/predicates below — so the
    //     default export (the only route to axios.create/get/post/request) is banned
    //     whatever local name it is bound to; also `axios/*` subpaths, dynamic
    //     import('axios'), and re-exporting from axios.
    // Not covered: an HTTP library other than axios (needs a package.json change a
    // reviewer sees), or reaching fetch through an indirection such as
    // `const f = window['fet' + 'ch']`.
    {
        files: ['src/**/*.{ts,tsx}'],
        ignores: [
            'src/services/client.ts',
            'src/services/auth.ts',
            'src/services/setup.ts',
            'src/**/*.test.ts',
            'src/**/*.test.tsx',
            'src/**/__tests__/**',
            'src/test/**',
        ],
        rules: {
            'no-restricted-imports': [
                'error',
                {
                    paths: [
                        {
                            name: 'axios',
                            allowImportNames: [
                                'isAxiosError',
                                'isCancel',
                                'AxiosError',
                                'CanceledError',
                                'AxiosResponse',
                                'AxiosRequestConfig',
                                'InternalAxiosRequestConfig',
                                'AxiosInstance',
                                'RawAxiosRequestHeaders',
                                'HttpStatusCode',
                            ],
                            message:
                                'INV-WEB-01: use apiClient (services/client.ts) or authApi (services/auth.ts); only types and isAxiosError/isCancel may be imported from axios here.',
                        },
                    ],
                    patterns: [
                        {
                            group: ['axios/*'],
                            message: 'INV-WEB-01: do not reach into axios internals; use apiClient/authApi.',
                        },
                    ],
                },
            ],
            'no-restricted-syntax': [
                'error',
                {
                    selector: "CallExpression[callee.type='Identifier'][callee.name='fetch']",
                    message: 'INV-WEB-01: raw fetch() bypasses apiClient (CSRF, credentials, session refresh).',
                },
                {
                    selector:
                        "CallExpression[callee.type='MemberExpression'][callee.object.name=/^(window|globalThis|self)$/][callee.property.name='fetch']",
                    message: 'INV-WEB-01: raw fetch() bypasses apiClient (CSRF, credentials, session refresh).',
                },
                {
                    selector: 'NewExpression[callee.name=/^(XMLHttpRequest|WebSocket|EventSource)$/]',
                    message: 'INV-WEB-01: raw network primitives bypass apiClient; add a service method instead.',
                },
                {
                    selector: "CallExpression[callee.object.name='navigator'][callee.property.name='sendBeacon']",
                    message: 'INV-WEB-01: navigator.sendBeacon bypasses apiClient.',
                },
                {
                    selector: "ImportExpression[source.value='axios']",
                    message: 'INV-WEB-01: dynamic import of axios bypasses the reviewed instances.',
                },
                {
                    selector:
                        "ExportNamedDeclaration[source.value='axios'], ExportAllDeclaration[source.value='axios']",
                    message: 'INV-WEB-01: re-exporting axios hands callers a way around apiClient.',
                },
            ],
        },
    },

    // Relax rules further for test files
    {
        files: ['src/**/*.test.ts', 'src/**/*.test.tsx', 'src/test/**/*'],
        rules: {
            '@typescript-eslint/no-unused-vars': 'off',
            'no-console': 'off',
            '@typescript-eslint/no-empty-function': 'off',
        },
    }
);
