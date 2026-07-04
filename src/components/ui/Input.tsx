import React from 'react';
import { clsx } from 'clsx';
import { cn } from '@/lib/utils';

type IconComponent = React.ComponentType<React.SVGProps<SVGSVGElement>>;

export interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
    label?: string;
    error?: string;
    helperText?: string;
    icon?: IconComponent;
}

const Input = React.forwardRef<HTMLInputElement, InputProps>(
    ({ className, label, error, helperText, icon: Icon, id, type, ...props }, ref) => {
        const generatedId = React.useId();
        const inputId = id || generatedId;
        const hasError = Boolean(error);

        return (
            <div className="relative w-full">
                {label && (
                    <label
                        htmlFor={inputId}
                        className={clsx(
                            'block text-sm font-medium mb-1',
                            hasError ? 'text-destructive' : 'text-base-secondary'
                        )}
                    >
                        {label}
                    </label>
                )}

                <div className="relative">
                    {Icon && (
                        <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                            <Icon
                                className={clsx(
                                    'h-5 w-5',
                                    hasError ? 'text-destructive' : 'text-base-muted'
                                )}
                            />
                        </div>
                    )}

                    <input
                        ref={ref}
                        id={inputId}
                        type={type}
                        aria-invalid={hasError}
                        data-slot="input"
                        className={cn(
                            "h-9 w-full min-w-0 rounded-md border border-input bg-transparent px-3 py-1 text-base shadow-xs transition-[color,box-shadow] outline-none placeholder:text-muted-foreground disabled:pointer-events-none disabled:cursor-not-allowed disabled:opacity-50 md:text-sm dark:bg-input/30",
                            "focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50",
                            "aria-invalid:border-destructive aria-invalid:ring-destructive/20 dark:aria-invalid:ring-destructive/40",
                            Icon && 'pl-10',
                            className
                        )}
                        {...props}
                    />
                </div>

                {error && (
                    <p className="mt-1 text-sm text-destructive" role="alert">
                        {error}
                    </p>
                )}

                {helperText && !error && (
                    <p className="mt-1 text-sm text-base-muted">
                        {helperText}
                    </p>
                )}
            </div>
        );
    }
);

Input.displayName = 'Input';

export { Input };
