import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import { resolve } from 'path';

export default defineConfig({
    plugins: [react()],
    resolve: {
        alias: { '@': resolve(import.meta.dirname, './src') },
    },
    test: {
        globals: true,
        environment: 'jsdom',
        setupFiles: ['./src/test/setup.ts'],
        css: true,
        exclude: ['**/node_modules/**', '**/dist/**', 'e2e/**'],
        coverage: {
            provider: 'v8',
            reporter: ['text', 'lcov'],
            reportsDirectory: './coverage',
            exclude: ['src/test/**', '**/__tests__/**', '**/*.test.*'],
        },
    },
});
