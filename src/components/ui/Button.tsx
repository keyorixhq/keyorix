import React from 'react';
import { clsx } from 'clsx';
import { LucideIcon } from 'lucide-react';

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
    variant?: 'primary' | 'secondary' | 'danger' | 'ghost' | 'outline';
    size?: 'sm' | 'md' | 'lg';
    loading?: boolean;
    icon?: LucideIcon;
    iconPosition?: 'left' | 'right';
    fullWidth?: boolean;
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
    (
        {
            className,
            variant = 'primary',
            size = 'md',
            loading = false,
            icon: Icon,
            iconPosition = 'left',
            fullWidth = false,
            disabled,
            children,
            ...props
        },
        ref
    ) => {
        const baseClasses = [
            'inline-flex items-center justify-center font-medium rounded-md',
            'focus:outline-none focus:ring-2 focus:ring-offset-2',
            'transition-colors duration-200',
            'disabled:opacity-50 disabled:cursor-not-allowed',
        ];

        const variantClasses = {
            primary: [
                'bg-blue-600 text-white hover:bg-blue-700',
                'focus:ring-blue-500',
                'disabled:hover:bg-blue-600',
            ],
            secondary: [
                'bg-gray-100 text-gray-900 hover:bg-gray-200',
                'focus:ring-gray-500',
                'disabled:hover:bg-gray-100',
            ],
            danger: [
                'bg-red-600 text-white hover:bg-red-700',
                'focus:ring-red-500',
                'disabled:hover:bg-red-600',
            ],
            ghost: [
                'text-gray-700 hover:bg-gray-100',
                'focus:ring-gray-500',
                'disabled:hover:bg-transparent',
            ],
            outline: [
                'border border-gray-300 text-gray-700 hover:bg-gray-50',
                'focus:ring-gray-500',
                'disabled:hover:bg-transparent',
            ],
        };

        const sizeClasses = {
            sm: 'px-3 py-1.5 text-sm',
            md: 'px-4 py-2 text-sm',
            lg: 'px-6 py-3 text-base',
        };

        const iconSizeClasses = {
            sm: 'h-4 w-4',
            md: 'h-4 w-4',
            lg: 'h-5 w-5',
        };

        const isDisabled = disabled || loading;

        return (
            <button
                ref={ref}
                className={clsx(
                    baseClasses,
                    variantClasses[variant],
                    sizeClasses[size],
                    fullWidth && 'w-full',
                    className
                )}
                disabled={isDisabled}
                {...props}
            >
                {loading && (
                    <svg
                        className={clsx(
                            'animate-spin',
                            iconSizeClasses[size],
                            children && (iconPosition === 'left' ? 'mr-2' : 'ml-2')
                        )}
                        fill="none"
                        viewBox="0 0 24 24"
                    >
                        <circle
                            className="opacity-25"
                            cx="12"
                            cy="12"
                            r="10"
                            stroke="currentColor"
                            strokeWidth="4"
                        />
                        <path
                            className="opacity-75"
                            fill="currentColor"
                            d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                        />
                    </svg>
                )}

                {!loading && Icon && iconPosition === 'left' && (
                    <Icon
                        className={clsx(
                            iconSizeClasses[size],
                            children && 'mr-2'
                        )}
                    />
                )}

                {children}

                {!loading && Icon && iconPosition === 'right' && (
                    <Icon
                        className={clsx(
                            iconSizeClasses[size],
                            children && 'ml-2'
                        )}
                    />
                )}
            </button>
        );
    }
);

Button.displayName = 'Button';

export { Button };