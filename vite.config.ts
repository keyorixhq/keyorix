import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { resolve } from 'path';
export default defineConfig(({ mode }) => ({
    plugins: [react()],
    resolve: {
        alias: {
            '@': resolve(import.meta.dirname, './src'),
        },
    },
    server: {
        port: 3000,
        proxy: {
            '/api': {
                target: 'https://localhost:8080',
                changeOrigin: true,
                secure: false,
            },
            '/auth': {
                target: 'https://localhost:8080',
                changeOrigin: true,
                secure: false,
            },
            '/system': {
                target: 'https://localhost:8080',
                changeOrigin: true,
                secure: false,
            },
            '/health': {
                target: 'https://localhost:8080',
                changeOrigin: true,
                secure: false,
            },
        },
    },
    build: {
        outDir: 'dist',
        // Never ship de-minified source structure in the production image;
        // still available for local `vite build --mode development` debugging.
        sourcemap: mode !== 'production',
        rollupOptions: {
            output: {
                manualChunks(id) {
                    if (!id.includes('node_modules')) return undefined;
                    if (id.includes('react-router')) return 'router';
                    if (id.includes('@tanstack/react-query')) return 'query';
                    if (id.includes('@headlessui') || id.includes('@heroicons')) return 'ui';
                    if (id.includes('/react-dom/') || id.includes('/react/')) return 'vendor';
                    return undefined;
                },
            },
        },
    },
    test: {
        globals: true,
        environment: 'jsdom',
        setupFiles: ['./src/test/setup.ts'],
        css: true,
    },
}));
