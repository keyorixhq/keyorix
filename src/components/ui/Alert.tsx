import React from 'react';
import { clsx } from 'clsx';
import {
    CheckCircleIcon,
    ExclamationTriangleIcon,
    InformationCircleIcon,
    XCircleIcon,
    XMarkIcon,
} from '@heroicons/react/24/outline';

export type AlertType = 'success' | 'error' | 'warning' | 'info';

export interface AlertProps {
    type: AlertType;
    title: string;
    message?: string;
    children?: React.ReactNode;
    dismissible?: boolean;
    onDismiss?: () => void;
    className?: string;
}

const Alert: React.FC<AlertProps> = ({
    type,
    title,
    message,
    children,
    dismissible = false,
    onDismiss,
    className,
}) => {
    const iconConfig = {
        success: {
            icon: CheckCircleIcon,
            bgColor: 'bg-green-50',
            borderColor: 'border-green-200',
            iconColor: 'text-green-400',
            titleColor: 'text-green-800',
            messageColor: 'text-green-700',
            buttonColor: 'text-green-500 hover:bg-green-100 focus:ring-green-600',
        },
        error: {
            icon: XCircleIcon,
            bgColor: 'bg-red-50',
            borderColor: 'border-red-200',
            iconColor: 'text-red-400',
            titleColor: 'text-red-800',
            messageColor: 'text-red-700',
            buttonColor: 'text-red-500 hover:bg-red-100 focus:ring-red-600',
        },
        warning: {
            icon: ExclamationTriangleIcon,
            bgColor: 'bg-yellow-50',
            borderColor: 'border-yellow-200',
            iconColor: 'text-yellow-400',
            titleColor: 'text-yellow-800',
            messageColor: 'text-yellow-700',
            buttonColor: 'text-yellow-500 hover:bg-yellow-100 focus:ring-yellow-600',
        },
        info: {
            icon: InformationCircleIcon,
            bgColor: 'bg-blue-50',
            borderColor: 'border-blue-200',
            iconColor: 'text-blue-400',
            titleColor: 'text-blue-800',
            messageColor: 'text-blue-700',
            buttonColor: 'text-blue-500 hover:bg-blue-100 focus:ring-blue-600',
        },
    };

    const config = iconConfig[type];
    const Icon = config.icon;

    return (
        <div className={clsx(
            'rounded-md border p-4',
            config.bgColor,
            config.borderColor,
            className
        )}>
            <div className="flex">
                <div className="flex-shrink-0">
                    <Icon className={clsx('h-5 w-5', config.iconColor)} aria-hidden="true" />
                </div>
                <div className="ml-3 flex-1">
                    <h3 className={clsx('text-sm font-medium', config.titleColor)}>
                        {title}
                    </h3>
                    {message && (
                        <div className={clsx('mt-2 text-sm', config.messageColor)}>
                            <p>{message}</p>
                        </div>
                    )}
                    {children && (
                        <div className={clsx('mt-2 text-sm', config.messageColor)}>
                            {children}
                        </div>
                    )}
                </div>
                {dismissible && onDismiss && (
                    <div className="ml-auto pl-3">
                        <div className="-mx-1.5 -my-1.5">
                            <button
                                type="button"
                                className={clsx(
                                    'inline-flex rounded-md p-1.5 focus:outline-none focus:ring-2 focus:ring-offset-2',
                                    config.buttonColor
                                )}
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

// Alert list component for multiple alerts
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

const AlertList: React.FC<AlertListProps> = ({
    alerts,
    onDismiss,
    className,
}) => {
    if (alerts.length === 0) {
        return null;
    }

    return (
        <div className={clsx('space-y-4', className)}>
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