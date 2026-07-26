import React, { useEffect, useState } from 'react';
import {
    CheckCircleIcon,
    ExclamationTriangleIcon,
    InformationCircleIcon,
    XCircleIcon,
    XMarkIcon,
} from '@heroicons/react/24/outline';
import { cn } from '@/lib/utils';

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

const ICONS: Record<ToastType, React.ElementType> = {
    success: CheckCircleIcon,
    error: XCircleIcon,
    warning: ExclamationTriangleIcon,
    info: InformationCircleIcon,
};

const COLORS: Record<ToastType, { icon: string; title: string; body: string; bg: string }> = {
    success: { icon: 'var(--success)', title: 'var(--success)', body: 'var(--success)', bg: 'var(--success-subtle)' },
    error: { icon: 'var(--error)', title: 'var(--error)', body: 'var(--error)', bg: 'var(--error-subtle)' },
    warning: { icon: 'var(--warning)', title: 'var(--warning)', body: 'var(--warning)', bg: 'var(--warning-subtle)' },
    info: { icon: 'var(--accent)', title: 'var(--accent-text)', body: 'var(--accent)', bg: 'var(--accent-subtle)' },
};

const LEAVE_MS = 200;

const ToastComponent: React.FC<ToastProps> = ({
    id,
    type,
    title,
    message,
    duration = 5000,
    persistent = false,
    onClose,
}) => {
    const [visible, setVisible] = useState(false);

    // Enter animation: flip to visible after one frame
    useEffect(() => {
        const raf = requestAnimationFrame(() => setVisible(true));
        return () => cancelAnimationFrame(raf);
    }, []);

    // Auto-dismiss
    useEffect(() => {
        if (persistent || duration <= 0) return;
        const t = setTimeout(() => {
            setVisible(false);
            setTimeout(() => onClose(id), LEAVE_MS);
        }, duration);
        return () => clearTimeout(t);
    }, [id, duration, persistent, onClose]);

    const handleClose = () => {
        setVisible(false);
        setTimeout(() => onClose(id), LEAVE_MS);
    };

    const c = COLORS[type];
    const Icon = ICONS[type];

    return (
        <div
            className={cn(
                'max-w-sm w-full shadow-lg rounded-lg pointer-events-auto overflow-hidden',
                'ring-1 ring-black/5 border',
                'transition-all ease-out',
                visible
                    ? 'opacity-100 translate-y-0 duration-300'
                    : 'opacity-0 translate-y-2 sm:translate-x-2 duration-200'
            )}
            style={{ backgroundColor: c.bg, borderColor: c.icon }}
        >
            <div className="p-4">
                <div className="flex items-start">
                    <div className="shrink-0">
                        <Icon className="h-6 w-6" aria-hidden="true" style={{ color: c.icon }} />
                    </div>
                    <div className="ml-3 w-0 flex-1 pt-0.5">
                        <p className="text-sm font-medium" style={{ color: c.title }}>
                            {title}
                        </p>
                        {message && (
                            <p className="mt-1 text-sm" style={{ color: c.body }}>
                                {message}
                            </p>
                        )}
                    </div>
                    <div className="ml-4 shrink-0 flex">
                        <button
                            className="rounded-md inline-flex focus:outline-hidden focus:ring-2 focus:ring-offset-2 transition-opacity hover:opacity-70"
                            style={{ color: c.icon }}
                            onClick={handleClose}
                        >
                            <span className="sr-only">Close</span>
                            <XMarkIcon className="h-5 w-5" aria-hidden="true" />
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
};

// ── ToastContainer ────────────────────────────────────────────────────────────

export interface ToastContainerProps {
    toasts: Toast[];
    onClose: (id: string) => void;
    position?: 'top-right' | 'top-left' | 'bottom-right' | 'bottom-left' | 'top-center' | 'bottom-center';
}

const POSITION: Record<NonNullable<ToastContainerProps['position']>, string> = {
    'top-right': 'top-0 right-0',
    'top-left': 'top-0 left-0',
    'bottom-right': 'bottom-0 right-0',
    'bottom-left': 'bottom-0 left-0',
    'top-center': 'top-0 left-1/2 -translate-x-1/2',
    'bottom-center': 'bottom-0 left-1/2 -translate-x-1/2',
};

const ToastContainer: React.FC<ToastContainerProps> = ({ toasts, onClose, position = 'top-right' }) => (
    <div
        aria-live="assertive"
        className={cn(
            'fixed z-50 inset-0 flex items-end px-4 py-6 pointer-events-none sm:p-6 sm:items-start',
            POSITION[position]
        )}
    >
        <div className="w-full flex flex-col items-center space-y-4 sm:items-end">
            {toasts.map((toast) => (
                <ToastComponent key={toast.id} {...toast} onClose={onClose} />
            ))}
        </div>
    </div>
);

export { ToastComponent, ToastContainer };
