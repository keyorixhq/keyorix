import React, { Component, ErrorInfo, ReactNode } from 'react';
import { ExclamationTriangleIcon, ArrowPathIcon } from '@heroicons/react/24/outline';
import { Button } from './Button';

interface ErrorBoundaryState {
    hasError: boolean;
    error: Error | null;
    errorInfo: ErrorInfo | null;
}

interface ErrorBoundaryProps {
    children: ReactNode;
    fallback?: ReactNode;
    onError?: (error: Error, errorInfo: ErrorInfo) => void;
}

class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
    constructor(props: ErrorBoundaryProps) {
        super(props);
        this.state = { hasError: false, error: null, errorInfo: null };
    }

    static getDerivedStateFromError(error: Error): ErrorBoundaryState {
        return { hasError: true, error, errorInfo: null };
    }

    override componentDidCatch(error: Error, errorInfo: ErrorInfo) {
        this.setState({ error, errorInfo });
        this.props.onError?.(error, errorInfo);
        if (import.meta.env.DEV) {
            console.error('ErrorBoundary caught:', error, errorInfo);
        }
    }

    handleRetry = () => {
        this.setState({ hasError: false, error: null, errorInfo: null });
    };

    handleReload = () => {
        window.location.reload();
    };

    override render() {
        if (!this.state.hasError) return this.props.children;

        if (this.props.fallback) return this.props.fallback;

        return (
            <div className="min-h-screen flex flex-col items-center justify-center bg-app px-4">
                <div className="w-full max-w-md rounded-lg border border-base bg-surface py-10 px-8 shadow-sm text-center">
                    <ExclamationTriangleIcon className="mx-auto h-12 w-12 text-[var(--warning)]" />
                    <h2 className="mt-4 text-lg font-semibold text-[var(--text-primary)]">Something went wrong</h2>
                    <p className="mt-2 text-sm text-[var(--text-secondary)]">
                        An unexpected error occurred. Try again or reload the page.
                    </p>

                    {import.meta.env.DEV && this.state.error && (
                        <details className="mt-4 text-left">
                            <summary className="cursor-pointer text-xs font-medium text-[var(--text-secondary)] hover:text-[var(--text-primary)]">
                                Error details (dev only)
                            </summary>
                            <pre className="mt-2 rounded-md bg-[var(--error-subtle)] p-3 text-xs text-[var(--error)] whitespace-pre-wrap break-words">
                                {this.state.error.toString()}
                                {this.state.errorInfo?.componentStack}
                            </pre>
                        </details>
                    )}

                    <div className="mt-6 flex flex-col gap-3 sm:flex-row">
                        <Button onClick={this.handleRetry} className="flex-1">
                            <ArrowPathIcon className="size-4" />
                            Try again
                        </Button>
                        <Button variant="outline" onClick={this.handleReload} className="flex-1">
                            Reload page
                        </Button>
                    </div>
                </div>
            </div>
        );
    }
}

// ── RouteErrorFallback ────────────────────────────────────────────────────────
// Inline error UI for route-level boundaries — keeps the nav visible while
// showing an error in the content area.

interface RouteErrorFallbackProps {
    error: Error;
    resetError: () => void;
}

const RouteErrorFallback: React.FC<RouteErrorFallbackProps> = ({ error, resetError }) => (
    <div className="flex min-h-96 items-center justify-center p-8">
        <div className="text-center">
            <ExclamationTriangleIcon className="mx-auto h-10 w-10 text-[var(--warning)]" />
            <h3 className="mt-3 text-base font-semibold text-[var(--text-primary)]">Page failed to load</h3>
            <p className="mt-1 text-sm text-[var(--text-secondary)]">
                {error.message || 'An unexpected error occurred'}
            </p>
            <Button variant="default" className="mt-5" onClick={resetError}>
                Try again
            </Button>
        </div>
    </div>
);

// ── RouteErrorBoundary ────────────────────────────────────────────────────────
// Stateful wrapper around RouteErrorFallback — used inside Layout so the nav
// stays mounted while the content area shows the error UI.

interface RouteErrorBoundaryState {
    hasError: boolean;
    error: Error | null;
}

class RouteErrorBoundary extends Component<{ children: ReactNode }, RouteErrorBoundaryState> {
    constructor(props: { children: ReactNode }) {
        super(props);
        this.state = { hasError: false, error: null };
    }

    static getDerivedStateFromError(error: Error): RouteErrorBoundaryState {
        return { hasError: true, error };
    }

    override componentDidCatch(error: Error, errorInfo: ErrorInfo) {
        if (import.meta.env.DEV) {
            console.error('RouteErrorBoundary caught:', error, errorInfo);
        }
    }

    reset = () => this.setState({ hasError: false, error: null });

    override render() {
        if (this.state.hasError && this.state.error) {
            return <RouteErrorFallback error={this.state.error} resetError={this.reset} />;
        }
        return this.props.children;
    }
}

export { ErrorBoundary, RouteErrorBoundary, RouteErrorFallback };
