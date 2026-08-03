import React from 'react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent } from '../../../test/test-utils';
import { ErrorBoundary, RouteErrorBoundary, RouteErrorFallback } from '../ErrorBoundary';

// Throws unconditionally on every render - used to force the boundary into
// its error state.
const Bomb: React.FC = () => {
    throw new Error('boom');
};

describe('ErrorBoundary', () => {
    it('renders children normally when no error is thrown', () => {
        render(
            <ErrorBoundary>
                <div>Safe content</div>
            </ErrorBoundary>
        );

        expect(screen.getByText('Safe content')).toBeInTheDocument();
    });

    describe('when a child throws during render', () => {
        let consoleErrorSpy: ReturnType<typeof vi.spyOn>;

        beforeEach(() => {
            // React (and this component's own componentDidCatch, in dev mode)
            // log the caught error to console.error. That's expected noise for
            // these intentionally-throwing tests, not a real failure.
            consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
        });

        afterEach(() => {
            consoleErrorSpy.mockRestore();
        });

        it('renders the default fallback UI', () => {
            render(
                <ErrorBoundary>
                    <Bomb />
                </ErrorBoundary>
            );

            expect(screen.getByText('Something went wrong')).toBeInTheDocument();
            expect(screen.getByText('An unexpected error occurred. Try again or reload the page.')).toBeInTheDocument();
            expect(screen.getByRole('button', { name: /try again/i })).toBeInTheDocument();
            expect(screen.getByRole('button', { name: /reload page/i })).toBeInTheDocument();
        });

        it('shows dev-only error details containing the caught error message', () => {
            render(
                <ErrorBoundary>
                    <Bomb />
                </ErrorBoundary>
            );

            expect(screen.getByText('Error details (dev only)')).toBeInTheDocument();
            expect(
                screen.getByText(
                    (_, element) =>
                        element?.tagName.toLowerCase() === 'pre' && !!element.textContent?.includes('Error: boom')
                )
            ).toBeInTheDocument();
        });

        it('renders a custom fallback instead of the default UI when provided', () => {
            render(
                <ErrorBoundary fallback={<div>Custom fallback UI</div>}>
                    <Bomb />
                </ErrorBoundary>
            );

            expect(screen.getByText('Custom fallback UI')).toBeInTheDocument();
            expect(screen.queryByText('Something went wrong')).not.toBeInTheDocument();
        });

        it('calls onError with the caught error and error info', () => {
            const onError = vi.fn();

            render(
                <ErrorBoundary onError={onError}>
                    <Bomb />
                </ErrorBoundary>
            );

            expect(onError).toHaveBeenCalledTimes(1);
            const [error, errorInfo] = onError.mock.calls[0];
            expect(error).toBeInstanceOf(Error);
            expect(error.message).toBe('boom');
            expect(errorInfo).toHaveProperty('componentStack');
        });

        it('recovers and renders children again after clicking "Try again"', () => {
            let shouldThrow = true;
            const ConditionalBomb: React.FC = () => {
                if (shouldThrow) throw new Error('boom');
                return <div>Recovered content</div>;
            };

            render(
                <ErrorBoundary>
                    <ConditionalBomb />
                </ErrorBoundary>
            );

            expect(screen.getByText('Something went wrong')).toBeInTheDocument();

            shouldThrow = false;
            fireEvent.click(screen.getByRole('button', { name: /try again/i }));

            expect(screen.getByText('Recovered content')).toBeInTheDocument();
            expect(screen.queryByText('Something went wrong')).not.toBeInTheDocument();
        });

        it('skips the dev-only console.error log when import.meta.env.DEV is false', () => {
            const originalDev = import.meta.env.DEV;
            (import.meta.env as { DEV: boolean }).DEV = false;

            try {
                render(
                    <ErrorBoundary>
                        <Bomb />
                    </ErrorBoundary>
                );

                expect(screen.getByText('Something went wrong')).toBeInTheDocument();
                expect(consoleErrorSpy).not.toHaveBeenCalledWith(
                    'ErrorBoundary caught:',
                    expect.any(Error),
                    expect.anything()
                );
                expect(screen.queryByText('Error details (dev only)')).not.toBeInTheDocument();
            } finally {
                (import.meta.env as { DEV: boolean }).DEV = originalDev;
            }
        });

        it('reloads the page when clicking "Reload page"', () => {
            const reloadMock = vi.fn();
            const originalLocation = window.location;
            Object.defineProperty(window, 'location', {
                configurable: true,
                value: { ...originalLocation, reload: reloadMock },
            });

            render(
                <ErrorBoundary>
                    <Bomb />
                </ErrorBoundary>
            );

            fireEvent.click(screen.getByRole('button', { name: /reload page/i }));

            expect(reloadMock).toHaveBeenCalledOnce();

            Object.defineProperty(window, 'location', {
                configurable: true,
                value: originalLocation,
            });
        });
    });
});

describe('RouteErrorFallback', () => {
    it('renders the error message and calls resetError when "Try again" is clicked', () => {
        const resetError = vi.fn();

        render(<RouteErrorFallback error={new Error('custom failure')} resetError={resetError} />);

        expect(screen.getByText('Page failed to load')).toBeInTheDocument();
        expect(screen.getByText('custom failure')).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: /try again/i }));
        expect(resetError).toHaveBeenCalledOnce();
    });

    it('falls back to a generic message when the error has no message', () => {
        render(<RouteErrorFallback error={new Error('')} resetError={vi.fn()} />);

        expect(screen.getByText('An unexpected error occurred')).toBeInTheDocument();
    });
});

describe('RouteErrorBoundary', () => {
    it('renders children normally when no error is thrown', () => {
        render(
            <RouteErrorBoundary>
                <div>Nested route content</div>
            </RouteErrorBoundary>
        );

        expect(screen.getByText('Nested route content')).toBeInTheDocument();
    });

    describe('when a child throws during render', () => {
        let consoleErrorSpy: ReturnType<typeof vi.spyOn>;

        beforeEach(() => {
            consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
        });

        afterEach(() => {
            consoleErrorSpy.mockRestore();
        });

        it('renders the RouteErrorFallback UI', () => {
            render(
                <RouteErrorBoundary>
                    <Bomb />
                </RouteErrorBoundary>
            );

            expect(screen.getByText('Page failed to load')).toBeInTheDocument();
            expect(screen.getByText('boom')).toBeInTheDocument();
        });

        it('recovers and renders children again after clicking "Try again"', () => {
            let shouldThrow = true;
            const ConditionalBomb: React.FC = () => {
                if (shouldThrow) throw new Error('boom');
                return <div>Recovered route content</div>;
            };

            render(
                <RouteErrorBoundary>
                    <ConditionalBomb />
                </RouteErrorBoundary>
            );

            expect(screen.getByText('Page failed to load')).toBeInTheDocument();

            shouldThrow = false;
            fireEvent.click(screen.getByRole('button', { name: /try again/i }));

            expect(screen.getByText('Recovered route content')).toBeInTheDocument();
            expect(screen.queryByText('Page failed to load')).not.toBeInTheDocument();
        });

        it('skips the dev-only console.error log when import.meta.env.DEV is false', () => {
            const originalDev = import.meta.env.DEV;
            (import.meta.env as { DEV: boolean }).DEV = false;

            try {
                render(
                    <RouteErrorBoundary>
                        <Bomb />
                    </RouteErrorBoundary>
                );

                expect(screen.getByText('Page failed to load')).toBeInTheDocument();
                expect(consoleErrorSpy).not.toHaveBeenCalledWith(
                    'RouteErrorBoundary caught:',
                    expect.any(Error),
                    expect.anything()
                );
            } finally {
                (import.meta.env as { DEV: boolean }).DEV = originalDev;
            }
        });
    });
});
