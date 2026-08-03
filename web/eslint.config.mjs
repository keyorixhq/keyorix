import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import reactHooks from 'eslint-plugin-react-hooks';
import reactRefresh from 'eslint-plugin-react-refresh';
import noUnsanitized from 'eslint-plugin-no-unsanitized';
import globals from 'globals';

export default tseslint.config(
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

    // Relax rules further for test files
    {
        files: ['src/**/*.test.ts', 'src/**/*.test.tsx', 'src/test/**/*'],
        rules: {
            '@typescript-eslint/no-unused-vars': 'off',
            'no-console': 'off',
            '@typescript-eslint/no-empty-function': 'off',
        },
    },
);
