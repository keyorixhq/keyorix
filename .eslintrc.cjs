module.exports = {
  root: true,
  env: { browser: true, es2020: true },
  parser: '@typescript-eslint/parser',
  parserOptions: {
    ecmaVersion: 'latest',
    sourceType: 'module',
    ecmaFeatures: { jsx: true },
  },
  plugins: ['@typescript-eslint', 'react-hooks', 'react-refresh'],
  extends: [
    'eslint:recommended',
    'plugin:@typescript-eslint/recommended',
    'plugin:react-hooks/recommended',
  ],
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
  },
  overrides: [
    {
      // Relax rules further for test files
      files: ['src/**/*.test.ts', 'src/**/*.test.tsx', 'src/test/**/*'],
      rules: {
        '@typescript-eslint/no-unused-vars': 'off',
        'no-console': 'off',
        '@typescript-eslint/no-empty-function': 'off',
      },
    },
  ],
  ignorePatterns: ['dist', 'node_modules', '*.config.ts', '*.config.js'],
};
