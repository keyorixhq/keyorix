import React, { useEffect } from 'react';
import { Transition } from '@headlessui/react';
import { clsx } from 'clsx';
import {
    CheckCircleIcon,
    ExclamationTriangleIcon,
    InformationCircleIcon,
    XCircleIcon,
    XMarkIcon,
} from '@heroicons/react/24/outline';

export type ToastType = 'success' | 'error' | 'warning' | 'info';

export interface Toast {
    id: string;
    type: ToastType;
    title: string;
    message?: string;
    duration?: number;
    persistent?: boolean;
}

export interface ToastProps extends Toast {
    onClose: (id: string) => void;
}

const ToastComponent: React.FC<ToastProps> = ({
    id,
    type,
    title,
    message,
    duration = 5000,
    persistent = false,
    onClose,
}) => {
    const [show, setShow] = React.useState(true);

    useEffect(() => {
        if (!persistent && duration > 0) {
            const timer = setTimeout(() => {
                setShow(false);
                setTimeout(() => onClose(id), 300); // Wait for animation to complete
            }, duration);

            return () => clearTimeout(timer);
        }
        return undefined;
    }, [id, duration, persistent, onClose]);

    const handleClose = () => {
        setShow(false);
        setTimeout(() => onClose(id), 300);
    };

    const iconConfig = {
        success: {
            icon: CheckCircleIcon,
            bgColor: 'bg-green-50',
            iconColor: 'text-green-400',
            titleColor: 'text-green-800',
            messageColor: 'text-green-700',
        },
        error: {
            icon: XCircleIcon,
            bgColor: 'bg-red-50',
            iconColor: 'text-red-400',
            titleColor: 'text-red-800',
            messageColor: 'text-red-700',
        },
        warning: {
            icon: ExclamationTriangleIcon,
            bgColor: 'bg-yellow-50',
            iconColor: 'text-yellow-400',
            titleColor: 'text-yellow-800',
            messageColor: 'text-yellow-700',
        },
        info: {
            icon: InformationCircleIcon,
            bgColor: 'bg-blue-50',
            iconColor: 'text-blue-400',
            titleColor: 'text-blue-800',
            messageColor: 'text-blue-700',
        },
    };

    const config = iconConfig[type];
    const Icon = config.icon;

    return (
        <Transition
            show={show}
            enter="transform ease-out duration-300 transition"
            enterFrom="translate-y-2 opacity-0 sm:translate-y-0 sm:translate-x-2"
            enterTo="translate-y-0 opacity-100 sm:translate-x-0"
            leave="transition ease-in duration-100"
            leaveFrom="opacity-100"
            leaveTo="opacity-0"
        >
            <div className={clsx('max-w-sm w-full shadow-lg rounded-lg pointer-events-auto ring-1 ring-black ring-opacity-5 overflow-hidden', config.bgColor)}>
                <div className="p-4">
                    <div className="flex items-start">
                        <div className="flex-shrink-0">
                            <Icon className={clsx('h-6 w-6', config.iconColor)} aria-hidden="true" />
                        </div>
                        <div className="ml-3 w-0 flex-1 pt-0.5">
                            <p className={clsx('text-sm font-medium', config.titleColor)}>
                                {title}
                            </p>
                            {message && (
                                <p className={clsx('mt-1 text-sm', config.messageColor)}>
                                    {message}
                                </p>
                            )}
                        </div>
                        <div className="ml-4 flex-shrink-0 flex">
                            <button
                                className={clsx(
                                    'rounded-md inline-flex focus:outline-none focus:ring-2 focus:ring-offset-2',
                                    config.bgColor,
                                    config.titleColor,
                                    'hover:' + config.messageColor
                                )}
                                onClick={handleClose}
                            >
                                <span className="sr-only">Close</span>
                                <XMarkIcon className="h-5 w-5" aria-hidden="true" />
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </Transition>
    );
};

// Toast container component
export interface ToastContainerProps {
    toasts: Toast[];
    onClose: (id: string) => void;
    position?: 'top-right' | 'top-left' | 'bottom-right' | 'bottom-left' | 'top-center' | 'bottom-center';
}

const ToastContainer: React.FC<ToastContainerProps> = ({
    toasts,
    onClose,
    position = 'top-right',
}) => {
    const positionClasses = {
        'top-right': 'top-0 right-0',
        'top-left': 'top-0 left-0',
        'bottom-right': 'bottom-0 right-0',
        'bottom-left': 'bottom-0 left-0',
        'top-center': 'top-0 left-1/2 transform -translate-x-1/2',
        'bottom-center': 'bottom-0 left-1/2 transform -translate-x-1/2',
    };

    return (
        <div
            aria-live="assertive"
            className={clsx(
                'fixed z-50 inset-0 flex items-end px-4 py-6 pointer-events-none sm:p-6 sm:items-start',
                positionClasses[position]
            )}
        >
            <div className="w-full flex flex-col items-center space-y-4 sm:items-end">
                {toasts.map((toast) => (
                    <ToastComponent
                        key={toast.id}
                        {...toast}
                        onClose={onClose}
                    />
                ))}
            </div>
        </div>
    );
};

export { ToastComponent, ToastContainer };