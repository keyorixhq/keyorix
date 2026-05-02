import React from 'react';
import { clsx } from 'clsx';

export interface TextareaProps extends React.TextareaHTMLAttributes<HTMLTextAreaElement> {
    label?: string;
    error?: string;
    helperText?: string;
    fullWidth?: boolean;
    resize?: 'none' | 'vertical' | 'horizontal' | 'both';
}

const Textarea = React.forwardRef<HTMLTextAreaElement, TextareaProps>(
    (
        {
            className,
            label,
            error,
            helperText,
            fullWidth = true,
            resize = 'vertical',
            id,
            rows = 3,
            ...props
        },
        ref
    ) => {
        const textareaId = id || `textarea-${Math.random().toString(36).substr(2, 9)}`;
        const hasError = Boolean(error);

        const baseTextareaClasses = [
            'block px-3 py-2 border rounded-md shadow-sm',
            'placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-offset-0',
            'transition-colors duration-200',
            'disabled:bg-gray-50 disabled:text-gray-500 disabled:cursor-not-allowed',
        ];

        const textareaStateClasses = hasError
            ? [
                'border-red-300 text-red-900 focus:ring-red-500 focus:border-red-500',
                'placeholder-red-300',
            ]
            : [
                'border-gray-300 focus:ring-blue-500 focus:border-blue-500',
            ];

        const resizeClasses = {
            none: 'resize-none',
            vertical: 'resize-y',
            horizontal: 'resize-x',
            both: 'resize',
        };

        const containerClasses = [
            fullWidth ? 'w-full' : 'w-auto',
        ];

        const textareaClasses = [
            ...baseTextareaClasses,
            ...textareaStateClasses,
            resizeClasses[resize],
            fullWidth ? 'w-full' : 'w-auto',
        ];

        return (
            <div className={clsx(containerClasses)}>
                {label && (
                    <label
                        htmlFor={textareaId}
                        className={clsx(
                            'block text-sm font-medium mb-1',
                            hasError ? 'text-red-700' : 'text-gray-700'
                        )}
                    >
                        {label}
                    </label>
                )}

                <textarea
                    ref={ref}
                    id={textareaId}
                    rows={rows}
                    className={clsx(textareaClasses, className)}
                    {...props}
                />

                {error && (
                    <p className="mt-1 text-sm text-red-600" role="alert">
                        {error}
                    </p>
                )}

                {helperText && !error && (
                    <p className="mt-1 text-sm text-gray-500">
                        {helperText}
                    </p>
                )}
            </div>
        );
    }
);

Textarea.displayName = 'Textarea';

export { Textarea };