import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import { resolve } from 'path';

export default defineConfig({
    plugins: [react()],
    resolve: {
        alias: { '@': resolve(__dirname, './src') },
    },
    test: {
        globals: true,
        environment: 'jsdom',
        setupFiles: ['./src/test/setup.ts'],
        css: true,
        exclude: [
            '**/node_modules/**',
            '**/dist/**',
            'e2e/**',
            'src/App.test.tsx',
            'src/test/accessibility.test.ts',
            'src/test/auth-integration.test.tsx',
            'src/test/i18n-test.ts',
            'src/test/utils.tsx',
            'src/hooks/__tests__/useAuth.test.ts',
            'src/store/__tests__/stores.test.ts',
            'src/components/secrets/__tests__/SecretForm.test.tsx',
            'src/components/layout/__tests__/AdminRoute.test.tsx',
            'src/components/layout/__tests__/ProtectedRoute.test.tsx',
            'src/components/layout/__tests__/PublicRoute.test.tsx',
        ],
    },
});
