import React, { ReactElement } from 'react';
import { render, RenderOptions } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter } from 'react-router-dom';
import { I18nextProvider } from 'react-i18next';
import i18n from '../lib/i18n';

// Create a custom render function that includes providers
const AllTheProviders = ({ children }: { children: React.ReactNode }) => {
    const queryClient = new QueryClient({
        defaultOptions: {
            queries: {
                retry: false,
                gcTime: 0,
            },
        },
    });

    return (
        <QueryClientProvider client={queryClient}>
            <BrowserRouter>
                <I18nextProvider i18n={i18n}>
                    {children}
                </I18nextProvider>
            </BrowserRouter>
        </QueryClientProvider>
    );
};

const customRender = (
    ui: ReactElement,
    options?: Omit<RenderOptions, 'wrapper'>
) => render(ui, { wrapper: AllTheProviders, ...options });

export * from '@testing-library/react';
export { customRender as render };

// Mock implementations for common hooks
export const mockAuthUser = {
    id: '1',
    email: 'test@example.com',
    name: 'Test User',
    role: 'user' as const,
    permissions: ['read:secrets', 'write:secrets'],
};

export const mockAdminUser = {
    id: '2',
    email: 'admin@example.com',
    name: 'Admin User',
    role: 'admin' as const,
    permissions: ['read:secrets', 'write:secrets', 'admin:users', 'admin:system'],
};

// Test data factories
export const createMockSecret = (overrides = {}) => ({
    id: '1',
    name: 'test-secret',
    type: 'password',
    value: 'secret-value',
    namespace: 'default',
    zone: 'production',
    environment: 'prod',
    tags: ['test'],
    metadata: {},
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    createdBy: 'test-user',
    ...overrides,
});

export const createMockShare = (overrides = {}) => ({
    id: '1',
    secretId: '1',
    sharedWith: 'user@example.com',
    permissions: 'read' as const,
    expiresAt: null,
    createdAt: new Date().toISOString(),
    createdBy: 'test-user',
    ...overrides,
});

// Mock API responses
export const mockApiResponse = <T,>(data: T, delay = 0) => {
    return new Promise<T>((resolve) => {
        setTimeout(() => resolve(data), delay);
    });
};

export const mockApiError = (message = 'API Error', status = 500) => {
    const error = new Error(message) as any;
    error.response = { status, data: { message } };
    return Promise.reject(error);
};

// Accessibility testing helpers
export const axeConfig = {
    rules: {
        // Disable color-contrast rule for tests (can be flaky)
        'color-contrast': { enabled: false },
    },
};

// Performance testing helpers
export const measureRenderTime = async (renderFn: () => void) => {
    const start = performance.now();
    renderFn();
    const end = performance.now();
    return end - start;
};

// Wait for async operations to complete
export const waitForLoadingToFinish = () => {
    return new Promise<void>(resolve => setTimeout(resolve, 0));
};