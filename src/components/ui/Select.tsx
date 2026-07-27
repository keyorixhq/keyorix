import * as React from 'react';
import { ChevronDownIcon } from '@heroicons/react/24/outline';
import { cn } from '@/lib/utils';

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
    ({ className, label, error, helperText, options, placeholder, fullWidth = true, id, ...rest }, ref) => {
        const generatedId = React.useId();
        const selectId = id ?? generatedId;
        const hasError = Boolean(error);
        const ariaDescribedBy = error ? `${selectId}-error` : helperText ? `${selectId}-hint` : undefined;

        return (
            <div className={cn(fullWidth ? 'w-full' : 'w-auto')}>
                {label && (
                    <label
                        htmlFor={selectId}
                        className={cn(
                            'block text-sm font-medium mb-1',
                            hasError ? 'text-[var(--error)]' : 'text-base-secondary'
                        )}
                    >
                        {label}
                    </label>
                )}

                <div className="relative">
                    <select
                        ref={ref}
                        id={selectId}
                        aria-invalid={hasError || undefined}
                        {...rest}
                        aria-describedby={ariaDescribedBy}
                        className={cn(
                            'block px-3 py-2 pr-10 rounded-md shadow-xs',
                            'border border-strong',
                            'text-sm appearance-none',
                            'transition-colors duration-150',
                            'focus:outline-hidden focus:ring-2 focus:ring-offset-0',
                            'disabled:opacity-50 disabled:cursor-not-allowed',
                            fullWidth ? 'w-full' : 'w-auto',
                            hasError ? 'border-[var(--error)] focus:ring-[var(--error)]' : 'focus:ring-[var(--accent)]',
                            className
                        )}
                    >
                        {placeholder && (
                            <option value="" disabled>
                                {placeholder}
                            </option>
                        )}
                        {options.map((option) => (
                            <option key={option.value} value={option.value} disabled={option.disabled}>
                                {option.label}
                            </option>
                        ))}
                    </select>

                    <div className="absolute inset-y-0 right-0 pr-3 flex items-center pointer-events-none">
                        <ChevronDownIcon
                            className={cn('h-4 w-4', hasError ? 'text-[var(--error)]' : 'text-base-muted')}
                        />
                    </div>
                </div>

                {error && (
                    <p id={`${selectId}-error`} className="mt-1 text-sm text-[var(--error)]" role="alert">
                        {error}
                    </p>
                )}

                {helperText && !error && (
                    <p id={`${selectId}-hint`} className="mt-1 text-sm text-base-muted">
                        {helperText}
                    </p>
                )}
            </div>
        );
    }
);

Select.displayName = 'Select';

export { Select };
