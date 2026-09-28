import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { resolve } from 'node:path';
export default defineConfig(({ mode }) => {
    // KEYORIX_DEV_PROXY_TARGET overrides the dev-server API proxy target
    // (default: the standard local TLS dev backend on :8080) -- SESSION-I's
    // web/e2e/real/*.spec.ts specs (via scripts/e2e/web-real-smoke.sh) point
    // this at a real, plain-HTTP keyorix-server they just booted, since the
    // main API client (src/services/client.ts) always uses a relative
    // baseURL and relies entirely on this proxy in dev, not on
    // VITE_API_BASE_URL (that env var only affects the separate, unrelated
    // unauthenticated setup-flow client in src/services/setup.ts).
    const proxyTarget = process.env.KEYORIX_DEV_PROXY_TARGET || 'https://localhost:8080';
    return {
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
                    target: proxyTarget,
                    changeOrigin: true,
                    secure: false,
                },
                '/auth': {
                    target: proxyTarget,
                    changeOrigin: true,
                    secure: false,
                },
                '/system': {
                    target: proxyTarget,
                    changeOrigin: true,
                    secure: false,
                },
                '/health': {
                    target: proxyTarget,
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
    };
});
