import React from 'react';
import { clsx } from 'clsx';

// Basic spinner component
export interface SpinnerProps {
    size?: 'sm' | 'md' | 'lg' | 'xl';
    color?: 'primary' | 'secondary' | 'white';
    className?: string;
}

const Spinner: React.FC<SpinnerProps> = ({
    size = 'md',
    color = 'primary',
    className,
}) => {
    const sizeClasses = {
        sm: 'h-4 w-4',
        md: 'h-6 w-6',
        lg: 'h-8 w-8',
        xl: 'h-12 w-12',
    };

    const colorClasses = {
        primary: 'text-blue-600',
        secondary: 'text-gray-600',
        white: 'text-white',
    };

    return (
        <svg
            className={clsx(
                'animate-spin',
                sizeClasses[size],
                colorClasses[color],
                className
            )}
            fill="none"
            viewBox="0 0 24 24"
        >
            <circle
                className="opacity-25"
                cx="12"
                cy="12"
                r="10"
                stroke="currentColor"
                strokeWidth="4"
            />
            <path
                className="opacity-75"
                fill="currentColor"
                d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
            />
        </svg>
    );
};

// Loading overlay component
export interface LoadingOverlayProps {
    isLoading: boolean;
    children: React.ReactNode;
    message?: string;
    className?: string;
}

const LoadingOverlay: React.FC<LoadingOverlayProps> = ({
    isLoading,
    children,
    message = 'Loading...',
    className,
}) => {
    return (
        <div className={clsx('relative', className)}>
            {children}
            {isLoading && (
                <div className="absolute inset-0 bg-white bg-opacity-75 flex items-center justify-center z-10">
                    <div className="flex flex-col items-center space-y-2">
                        <Spinner size="lg" />
                        <p className="text-sm text-gray-600">{message}</p>
                    </div>
                </div>
            )}
        </div>
    );
};

// Skeleton loading component
export interface SkeletonProps {
    className?: string;
    lines?: number;
    height?: string;
}

const Skeleton: React.FC<SkeletonProps> = ({
    className,
    lines = 1,
    height = 'h-4',
}) => {
    return (
        <div className={clsx('animate-pulse space-y-2', className)}>
            {Array.from({ length: lines }).map((_, index) => (
                <div
                    key={index}
                    className={clsx(
                        'bg-gray-200 rounded',
                        height,
                        index === lines - 1 && lines > 1 ? 'w-3/4' : 'w-full'
                    )}
                />
            ))}
        </div>
    );
};

// Progress bar component
export interface ProgressProps {
    value: number;
    max?: number;
    size?: 'sm' | 'md' | 'lg';
    color?: 'primary' | 'success' | 'warning' | 'danger';
    showLabel?: boolean;
    label?: string;
    className?: string;
}

const Progress: React.FC<ProgressProps> = ({
    value,
    max = 100,
    size = 'md',
    color = 'primary',
    showLabel = false,
    label,
    className,
}) => {
    const percentage = Math.min(Math.max((value / max) * 100, 0), 100);

    const sizeClasses = {
        sm: 'h-1',
        md: 'h-2',
        lg: 'h-3',
    };

    const colorClasses = {
        primary: 'bg-blue-600',
        success: 'bg-green-600',
        warning: 'bg-yellow-600',
        danger: 'bg-red-600',
    };

    return (
        <div className={clsx('w-full', className)}>
            {(showLabel || label) && (
                <div className="flex justify-between items-center mb-1">
                    <span className="text-sm font-medium text-gray-700">
                        {label || `${Math.round(percentage)}%`}
                    </span>
                    {showLabel && !label && (
                        <span className="text-sm text-gray-500">
                            {value}/{max}
                        </span>
                    )}
                </div>
            )}
            <div className={clsx('w-full bg-gray-200 rounded-full', sizeClasses[size])}>
                <div
                    className={clsx(
                        'rounded-full transition-all duration-300 ease-in-out',
                        sizeClasses[size],
                        colorClasses[color]
                    )}
                    style={{ width: `${percentage}%` }}
                />
            </div>
        </div>
    );
};

// Full page loading component
export interface LoadingPageProps {
    message?: string;
    className?: string;
}

const LoadingPage: React.FC<LoadingPageProps> = ({
    message = 'Loading...',
    className,
}) => {
    return (
        <div className={clsx(
            'min-h-screen flex items-center justify-center bg-gray-50',
            className
        )}>
            <div className="text-center">
                <Spinner size="xl" />
                <p className="mt-4 text-lg text-gray-600">{message}</p>
            </div>
        </div>
    );
};

const Loading = LoadingPage;

export { Spinner, LoadingOverlay, Skeleton, Progress, LoadingPage, Loading };