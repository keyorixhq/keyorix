import React from 'react';
import { clsx } from 'clsx';
import { ChevronDownIcon } from '@heroicons/react/24/outline';

export interface SelectOption {
    value: string;
    label: string;
    disabled?: boolean;
}

export interface SelectProps extends Omit<React.SelectHTMLAttributes<HTMLSelectElement>, 'children'> {
    label?: string;
    error?: string;
    helperText?: string;
    options: SelectOption[];
    placeholder?: string;
    fullWidth?: boolean;
}

const Select = React.forwardRef<HTMLSelectElement, SelectProps>(
    (
        {
            className,
            label,
            error,
            helperText,
            options,
            placeholder,
            fullWidth = true,
            id,
            ...props
        },
        ref
    ) => {
        const selectId = id || `select-${Math.random().toString(36).substr(2, 9)}`;
        const hasError = Boolean(error);

        const baseSelectClasses = [
            'block px-3 py-2 pr-10 border rounded-md shadow-sm',
            'bg-white focus:outline-none focus:ring-2 focus:ring-offset-0',
            'transition-colors duration-200 appearance-none',
            'disabled:bg-gray-50 disabled:text-gray-500 disabled:cursor-not-allowed',
        ];

        const selectStateClasses = hasError
            ? [
                'border-red-300 text-red-900 focus:ring-red-500 focus:border-red-500',
            ]
            : [
                'border-gray-300 focus:ring-blue-500 focus:border-blue-500',
            ];

        const containerClasses = [
            fullWidth ? 'w-full' : 'w-auto',
        ];

        const selectClasses = [
            ...baseSelectClasses,
            ...selectStateClasses,
            fullWidth ? 'w-full' : 'w-auto',
        ];

        return (
            <div className={clsx(containerClasses)}>
                {label && (
                    <label
                        htmlFor={selectId}
                        className={clsx(
                            'block text-sm font-medium mb-1',
                            hasError ? 'text-red-700' : 'text-gray-700'
                        )}
                    >
                        {label}
                    </label>
                )}

                <div className="relative">
                    <select
                        ref={ref}
                        id={selectId}
                        className={clsx(selectClasses, className)}
                        {...props}
                    >
                        {placeholder && (
                            <option value="" disabled>
                                {placeholder}
                            </option>
                        )}
                        {options.map((option) => (
                            <option
                                key={option.value}
                                value={option.value}
                                disabled={option.disabled}
                            >
                                {option.label}
                            </option>
                        ))}
                    </select>

                    <div className="absolute inset-y-0 right-0 pr-3 flex items-center pointer-events-none">
                        <ChevronDownIcon
                            className={clsx(
                                'h-5 w-5',
                                hasError ? 'text-red-400' : 'text-gray-400'
                            )}
                        />
                    </div>
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

Select.displayName = 'Select';

export { Select };