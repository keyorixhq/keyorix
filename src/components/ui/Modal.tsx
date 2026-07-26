import React from 'react';
import { Dialog } from 'radix-ui';
import { XMarkIcon } from '@heroicons/react/24/outline';
import { cn } from '@/lib/utils';

export interface ModalProps {
    isOpen: boolean;
    onClose: () => void;
    title?: string;
    children: React.ReactNode;
    size?: 'sm' | 'md' | 'lg' | 'xl' | 'full';
    showCloseButton?: boolean;
    closeOnOverlayClick?: boolean;
    className?: string;
}

const SIZE: Record<NonNullable<ModalProps['size']>, string> = {
    sm: 'max-w-md',
    md: 'max-w-lg',
    lg: 'max-w-2xl',
    xl: 'max-w-4xl',
    full: 'max-w-full mx-4',
};

const Modal: React.FC<ModalProps> = ({
    isOpen,
    onClose,
    title,
    children,
    size = 'md',
    showCloseButton = true,
    closeOnOverlayClick = true,
    className,
}) => (
    <Dialog.Root
        open={isOpen}
        onOpenChange={(open) => {
            if (!open) onClose();
        }}
    >
        <Dialog.Portal>
            {/* Backdrop */}
            <Dialog.Overlay
                className={cn(
                    'fixed inset-0 z-50 bg-black/40',
                    'data-[state=open]:animate-in data-[state=open]:fade-in-0',
                    'data-[state=closed]:animate-out data-[state=closed]:fade-out-0'
                )}
                onClick={closeOnOverlayClick ? undefined : (e) => e.stopPropagation()}
            />

            {/* Panel */}
            <Dialog.Content
                {...(!closeOnOverlayClick && { onInteractOutside: (e) => e.preventDefault() })}
                onEscapeKeyDown={() => onClose()}
                className={cn(
                    'fixed left-1/2 top-1/2 z-50 w-full -translate-x-1/2 -translate-y-1/2',
                    'rounded-lg border shadow-xl overflow-hidden',
                    'data-[state=open]:animate-in data-[state=open]:fade-in-0 data-[state=open]:zoom-in-95',
                    'data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=closed]:zoom-out-95',
                    SIZE[size],
                    className
                )}
                style={{ backgroundColor: 'var(--bg-surface)', borderColor: 'var(--border)' }}
            >
                {(title || showCloseButton) && (
                    <div
                        className="flex items-center justify-between px-6 py-4 border-b"
                        style={{ borderColor: 'var(--border)' }}
                    >
                        {title && (
                            <Dialog.Title
                                className="text-lg font-medium leading-6"
                                style={{ color: 'var(--text-primary)' }}
                            >
                                {title}
                            </Dialog.Title>
                        )}
                        {showCloseButton && (
                            <Dialog.Close
                                className="rounded-md focus:outline-hidden focus:ring-2 focus:ring-[var(--accent)] transition-colors"
                                style={{ color: 'var(--text-muted)' }}
                            >
                                <span className="sr-only">Close</span>
                                <XMarkIcon className="h-6 w-6" aria-hidden="true" />
                            </Dialog.Close>
                        )}
                    </div>
                )}

                <div className="px-6 py-4">{children}</div>
            </Dialog.Content>
        </Dialog.Portal>
    </Dialog.Root>
);

export { Modal };
