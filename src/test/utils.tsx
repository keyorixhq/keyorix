/* eslint-disable react-refresh/only-export-components */
import { ReactElement } from 'react';
import { render, RenderOptions } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter } from 'react-router-dom';
import { I18nextProvider } from 'react-i18next';
import i18n from './i18n-test';

// Create a custom render function that includes providers
const AllTheProviders = ({ children }: { children: React.ReactNode }) => {
    // Create a new QueryClient for each test to avoid state leakage
    const queryClient = new QueryClient({
        defaultOptions: {
            queries: {
                retry: false,
                gcTime: 0,
            },
            mutations: {
                retry: false,
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

// Re-export everything
export * from '@testing-library/react';
export { customRender as render };

// Custom render function for components that need specific providers
export const renderWithQueryClient = (
    ui: ReactElement,
    queryClient?: QueryClient,
    options?: Omit<RenderOptions, 'wrapper'>
) => {
    const client = queryClient || new QueryClient({
        defaultOptions: {
            queries: {
                retry: false,
                gcTime: 0,
            },
            mutations: {
                retry: false,
            },
        },
    });

    const Wrapper = ({ children }: { children: React.ReactNode }) => (
        <QueryClientProvider client={client}>
            <BrowserRouter>
                <I18nextProvider i18n={i18n}>
                    {children}
                </I18nextProvider>
            </BrowserRouter>
        </QueryClientProvider>
    );

    return render(ui, { wrapper: Wrapper, ...options });
};

// Render function for testing components without router
export const renderWithoutRouter = (
    ui: ReactElement,
    options?: Omit<RenderOptions, 'wrapper'>
) => {
    const queryClient = new QueryClient({
        defaultOptions: {
            queries: {
                retry: false,
                gcTime: 0,
            },
            mutations: {
                retry: false,
            },
        },
    });

    const Wrapper = ({ children }: { children: React.ReactNode }) => (
        <QueryClientProvider client={queryClient}>
            <I18nextProvider i18n={i18n}>
                {children}
            </I18nextProvider>
        </QueryClientProvider>
    );

    return render(ui, { wrapper: Wrapper, ...options });
};