import React from 'react';
import { clsx } from 'clsx';
import { LucideIcon } from 'lucide-react';

export interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
    label?: string;
    error?: string;
    helperText?: string;
    leftIcon?: LucideIcon;
    rightIcon?: LucideIcon;
    onRightIconClick?: () => void;
    fullWidth?: boolean;
}

const Input = React.forwardRef<HTMLInputElement, InputProps>(
    (
        {
            className,
            label,
            error,
            helperText,
            leftIcon: LeftIcon,
            rightIcon: RightIcon,
            onRightIconClick,
            fullWidth = true,
            id,
            ...props
        },
        ref
    ) => {
        const inputId = id || `input-${Math.random().toString(36).substr(2, 9)}`;
        const hasError = Boolean(error);

        const baseInputClasses = [
            'block px-3 py-2 border rounded-md shadow-sm',
            'placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-offset-0',
            'transition-colors duration-200',
            'disabled:bg-gray-50 disabled:text-gray-500 disabled:cursor-not-allowed',
        ];

        const inputStateClasses = hasError
            ? [
                'border-red-300 text-red-900 focus:ring-red-500 focus:border-red-500',
                'placeholder-red-300',
            ]
            : [
                'border-gray-300 focus:ring-blue-500 focus:border-blue-500',
            ];

        const containerClasses = [
            'relative',
            fullWidth ? 'w-full' : 'w-auto',
        ];

        const inputClasses = [
            ...baseInputClasses,
            ...inputStateClasses,
            LeftIcon && 'pl-10',
            RightIcon && 'pr-10',
            fullWidth ? 'w-full' : 'w-auto',
        ];

        return (
            <div className={clsx(containerClasses)}>
                {label && (
                    <label
                        htmlFor={inputId}
                        className={clsx(
                            'block text-sm font-medium mb-1',
                            hasError ? 'text-red-700' : 'text-gray-700'
                        )}
                    >
                        {label}
                    </label>
                )}

                <div className="relative">
                    {LeftIcon && (
                        <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                            <LeftIcon
                                className={clsx(
                                    'h-5 w-5',
                                    hasError ? 'text-red-400' : 'text-gray-400'
                                )}
                            />
                        </div>
                    )}

                    <input
                        ref={ref}
                        id={inputId}
                        className={clsx(inputClasses, className)}
                        {...props}
                    />

                    {RightIcon && (
                        <div
                            className={clsx(
                                'absolute inset-y-0 right-0 pr-3 flex items-center',
                                onRightIconClick ? 'cursor-pointer' : 'pointer-events-none'
                            )}
                            onClick={onRightIconClick}
                        >
                            <RightIcon
                                className={clsx(
                                    'h-5 w-5',
                                    hasError ? 'text-red-400' : 'text-gray-400',
                                    onRightIconClick && 'hover:text-gray-600'
                                )}
                            />
                        </div>
                    )}
                </div>

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

Input.displayName = 'Input';

export { Input };