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
        this.state = {
            hasError: false,
            error: null,
            errorInfo: null,
        };
    }

    static getDerivedStateFromError(error: Error): ErrorBoundaryState {
        return {
            hasError: true,
            error,
            errorInfo: null,
        };
    }

    override componentDidCatch(error: Error, errorInfo: ErrorInfo) {
        this.setState({
            error,
            errorInfo,
        });

        // Call the onError callback if provided
        if (this.props.onError) {
            this.props.onError(error, errorInfo);
        }

        // Log error to console in development
        if (import.meta.env.DEV) {
            console.error('Error caught by ErrorBoundary:', error);
            console.error('Error info:', errorInfo);
        }
    }

    handleRetry = () => {
        this.setState({
            hasError: false,
            error: null,
            errorInfo: null,
        });
    };

    handleReload = () => {
        window.location.reload();
    };

    override render() {
        if (this.state.hasError) {
            // Custom fallback UI
            if (this.props.fallback) {
                return this.props.fallback;
            }

            // Default error UI
            return (
                <div className="min-h-screen bg-gray-50 flex flex-col justify-center py-12 sm:px-6 lg:px-8">
                    <div className="sm:mx-auto sm:w-full sm:max-w-md">
                        <div className="bg-white py-8 px-4 shadow sm:rounded-lg sm:px-10">
                            <div className="text-center">
                                <ExclamationTriangleIcon className="mx-auto h-12 w-12 text-red-400" />
                                <h2 className="mt-4 text-lg font-medium text-gray-900">
                                    Something went wrong
                                </h2>
                                <p className="mt-2 text-sm text-gray-600">
                                    We're sorry, but something unexpected happened. Please try again.
                                </p>

                                {import.meta.env.DEV && this.state.error && (
                                    <details className="mt-4 text-left">
                                        <summary className="cursor-pointer text-sm font-medium text-gray-700 hover:text-gray-900">
                                            Error Details (Development)
                                        </summary>
                                        <div className="mt-2 p-3 bg-gray-100 rounded-md">
                                            <pre className="text-xs text-red-600 whitespace-pre-wrap">
                                                {this.state.error.toString()}
                                                {this.state.errorInfo?.componentStack}
                                            </pre>
                                        </div>
                                    </details>
                                )}

                                <div className="mt-6 flex flex-col space-y-3 sm:flex-row sm:space-y-0 sm:space-x-3">
                                    <Button
                                        variant="primary"
                                        onClick={this.handleRetry}
                                        icon={ArrowPathIcon}
                                        className="flex-1"
                                    >
                                        Try Again
                                    </Button>
                                    <Button
                                        variant="outline"
                                        onClick={this.handleReload}
                                        className="flex-1"
                                    >
                                        Reload Page
                                    </Button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            );
        }

        return this.props.children;
    }
}

// Hook-based error boundary for functional components
interface ErrorFallbackProps {
    error: Error;
    resetError: () => void;
}

const ErrorFallback: React.FC<ErrorFallbackProps> = ({ error, resetError }) => {
    return (
        <div className="min-h-96 flex items-center justify-center">
            <div className="text-center">
                <ExclamationTriangleIcon className="mx-auto h-12 w-12 text-red-400" />
                <h3 className="mt-4 text-lg font-medium text-gray-900">
                    Something went wrong
                </h3>
                <p className="mt-2 text-sm text-gray-600">
                    {error.message || 'An unexpected error occurred'}
                </p>
                <div className="mt-6">
                    <Button variant="primary" onClick={resetError}>
                        Try again
                    </Button>
                </div>
            </div>
        </div>
    );
};

// Simple error boundary wrapper for specific components
interface ComponentErrorBoundaryProps {
    children: ReactNode;
    componentName?: string;
}

const ComponentErrorBoundary: React.FC<ComponentErrorBoundaryProps> = ({
    children,
    componentName = 'Component',
}) => {
    return (
        <ErrorBoundary
            fallback={
                <div className="p-4 bg-red-50 border border-red-200 rounded-md">
                    <div className="flex">
                        <ExclamationTriangleIcon className="h-5 w-5 text-red-400" />
                        <div className="ml-3">
                            <h3 className="text-sm font-medium text-red-800">
                                {componentName} Error
                            </h3>
                            <p className="mt-1 text-sm text-red-700">
                                This component failed to load. Please refresh the page or try again later.
                            </p>
                        </div>
                    </div>
                </div>
            }
        >
            {children}
        </ErrorBoundary>
    );
};

export { ErrorBoundary, ErrorFallback, ComponentErrorBoundary };