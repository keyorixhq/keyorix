import React from 'react';
import { cva, type VariantProps } from 'class-variance-authority';
import {
    CheckCircleIcon,
    ExclamationTriangleIcon,
    InformationCircleIcon,
    XCircleIcon,
    XMarkIcon,
} from '@heroicons/react/24/outline';
import { cn } from '@/lib/utils';

// ── Variants ─────────────────────────────────────────────────────────────────

const alertVariants = cva(
    'rounded-md border p-4',
    {
        variants: {
            type: {
                success: '[--alert-icon:var(--success)] [--alert-bg:var(--success-subtle)] [--alert-border:var(--success)] [--alert-title:var(--success)] [--alert-body:var(--success)]',
                error:   '[--alert-icon:var(--error)]   [--alert-bg:var(--error-subtle)]   [--alert-border:var(--error)]   [--alert-title:var(--error)]   [--alert-body:var(--error)]',
                warning: '[--alert-icon:var(--warning)] [--alert-bg:var(--warning-subtle)] [--alert-border:var(--warning)] [--alert-title:var(--warning)] [--alert-body:var(--warning)]',
                info:    '[--alert-icon:var(--accent)]  [--alert-bg:var(--accent-subtle)]  [--alert-border:var(--accent)]  [--alert-title:var(--accent-text)] [--alert-body:var(--accent)]',
            },
        },
    }
);

// ── Types ─────────────────────────────────────────────────────────────────────

export type AlertType = 'success' | 'error' | 'warning' | 'info';

export interface AlertProps extends VariantProps<typeof alertVariants> {
    type: AlertType;
    title?: string;
    message?: string;
    children?: React.ReactNode;
    dismissible?: boolean;
    onDismiss?: () => void;
    className?: string;
}

const ICONS: Record<AlertType, React.ElementType> = {
    success: CheckCircleIcon,
    error:   XCircleIcon,
    warning: ExclamationTriangleIcon,
    info:    InformationCircleIcon,
};

// ── Alert ─────────────────────────────────────────────────────────────────────

const Alert: React.FC<AlertProps> = ({
    type,
    title,
    message,
    children,
    dismissible = false,
    onDismiss,
    className,
}) => {
    const Icon = ICONS[type];

    return (
        <div
            className={cn(alertVariants({ type }), className)}
            style={{
                backgroundColor: 'var(--alert-bg)',
                borderColor: 'var(--alert-border)',
            }}
        >
            <div className="flex">
                <div className="shrink-0">
                    <Icon
                        className="h-5 w-5"
                        aria-hidden="true"
                        style={{ color: 'var(--alert-icon)' }}
                    />
                </div>
                <div className="ml-3 flex-1">
                    {title && (
                        <h3
                            className="text-sm font-medium"
                            style={{ color: 'var(--alert-title)' }}
                        >
                            {title}
                        </h3>
                    )}
                    {message && (
                        <div className="mt-2 text-sm" style={{ color: 'var(--alert-body)' }}>
                            <p>{message}</p>
                        </div>
                    )}
                    {children && (
                        <div className="mt-2 text-sm" style={{ color: 'var(--alert-body)' }}>
                            {children}
                        </div>
                    )}
                </div>
                {dismissible && onDismiss && (
                    <div className="ml-auto pl-3">
                        <div className="-mx-1.5 -my-1.5">
                            <button
                                type="button"
                                className="inline-flex rounded-md p-1.5 focus:outline-hidden focus:ring-2 focus:ring-offset-2 transition-colors"
                                style={{ color: 'var(--alert-icon)' }}
                                onClick={onDismiss}
                            >
                                <span className="sr-only">Dismiss</span>
                                <XMarkIcon className="h-5 w-5" aria-hidden="true" />
                            </button>
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
};

// ── AlertList ─────────────────────────────────────────────────────────────────

export interface AlertListProps {
    alerts: Array<{
        id: string;
        type: AlertType;
        title: string;
        message?: string;
        dismissible?: boolean;
    }>;
    onDismiss?: (id: string) => void;
    className?: string;
}

const AlertList: React.FC<AlertListProps> = ({ alerts, onDismiss, className }) => {
    if (alerts.length === 0) return null;

    return (
        <div className={cn('space-y-4', className)}>
            {alerts.map((alert) => (
                <Alert
                    key={alert.id}
                    type={alert.type}
                    title={alert.title}
                    {...(alert.message && { message: alert.message })}
                    {...(alert.dismissible !== undefined && { dismissible: alert.dismissible })}
                    {...(onDismiss && { onDismiss: () => onDismiss(alert.id) })}
                />
            ))}
        </div>
    );
};

export { Alert, AlertList };
