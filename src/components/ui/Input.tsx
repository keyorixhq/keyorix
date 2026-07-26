import React from 'react';
import { cn } from '@/lib/utils';

export interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
    label?: string;
    error?: string | undefined;
    helperText?: string;
    icon?: React.ComponentType<React.SVGProps<SVGSVGElement>>;  // left-side SVG icon component
    trailingElement?: React.ReactNode; // right-side element (e.g. show/hide toggle)
}

const Input = React.forwardRef<HTMLInputElement, InputProps>(
    ({ className, label, error, helperText, icon: Icon, trailingElement, id, type, ...props }, ref) => {
        const generatedId = React.useId();
        const inputId = id ?? generatedId;
        const hasError = Boolean(error);

        return (
            <div className="relative w-full">
                {label && (
                    <label
                        htmlFor={inputId}
                        className={cn(
                            'block text-sm font-medium mb-1',
                            hasError ? 'text-destructive' : 'text-base-secondary',
                        )}
                    >
                        {label}
                    </label>
                )}

                <div className="relative">
                    {Icon && (
                        <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                            <Icon className="h-5 w-5 text-base-muted" />
                        </div>
                    )}

                    <input
                        ref={ref}
                        id={inputId}
                        type={type}
                        aria-invalid={hasError || undefined}
                        aria-describedby={
                            error ? `${inputId}-error` :
                            helperText ? `${inputId}-hint` :
                            undefined
                        }
                        data-slot="input"
                        className={cn(
                            'h-9 w-full min-w-0 rounded-md border border-input bg-transparent px-3 py-1',
                            'text-base shadow-xs transition-[color,box-shadow] outline-none',
                            'placeholder:text-muted-foreground',
                            'disabled:pointer-events-none disabled:cursor-not-allowed disabled:opacity-50',
                            'focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50',
                            'aria-invalid:border-destructive aria-invalid:ring-destructive/20',
                            'md:text-sm',
                            !!Icon && 'pl-10',
                            trailingElement && 'pr-10',
                            className,
                        )}
                        {...props}
                    />

                    {trailingElement && (
                        <div className="absolute inset-y-0 right-0 pr-3 flex items-center">
                            {trailingElement}
                        </div>
                    )}
                </div>

                {error && (
                    <p id={`${inputId}-error`} className="mt-1 text-sm text-destructive" role="alert">
                        {error}
                    </p>
                )}

                {helperText && !error && (
                    <p id={`${inputId}-hint`} className="mt-1 text-sm text-base-muted">
                        {helperText}
                    </p>
                )}
            </div>
        );
    },
);

Input.displayName = 'Input';

export { Input };
