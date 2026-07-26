import React from 'react';
import { DropdownMenu } from 'radix-ui';
import { ChevronDownIcon } from '@heroicons/react/24/outline';
import { cn } from '@/lib/utils';

type IconComponent = React.ComponentType<React.SVGProps<SVGSVGElement>>;

export interface DropdownItem {
    label: string;
    value: string;
    icon?: IconComponent;
    disabled?: boolean;
    danger?: boolean;
    onClick?: () => void;
}

export interface DropdownProps {
    trigger: React.ReactNode;
    items: DropdownItem[];
    align?: 'left' | 'right';
    className?: string;
}

const Dropdown: React.FC<DropdownProps> = ({ trigger, items, align = 'right', className }) => (
    <DropdownMenu.Root>
        <DropdownMenu.Trigger asChild>
            <div className={cn('relative inline-block text-left cursor-pointer', className)}>{trigger}</div>
        </DropdownMenu.Trigger>

        <DropdownMenu.Portal>
            <DropdownMenu.Content
                align={align === 'right' ? 'end' : 'start'}
                sideOffset={8}
                className={cn(
                    'z-50 min-w-56 rounded-md border shadow-lg py-1',
                    'data-[state=open]:animate-in data-[state=open]:fade-in-0 data-[state=open]:zoom-in-95',
                    'data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=closed]:zoom-out-95'
                )}
                style={{ backgroundColor: 'var(--bg-surface)', borderColor: 'var(--border)' }}
            >
                {(items ?? []).map((item) => {
                    const Icon = item.icon;
                    return (
                        <DropdownMenu.Item
                            key={item.value}
                            disabled={item.disabled ?? false}
                            {...(item.onClick && { onSelect: item.onClick })}
                            className={cn(
                                'group flex w-full items-center px-4 py-2 text-sm outline-none cursor-pointer',
                                'data-[highlighted]:bg-subtle',
                                item.disabled && 'opacity-50 cursor-not-allowed',
                                item.danger
                                    ? 'text-[var(--error)] data-[highlighted]:bg-[var(--error-subtle)]'
                                    : 'text-base-secondary'
                            )}
                        >
                            {Icon && (
                                <Icon
                                    className={cn(
                                        'mr-3 h-4 w-4 shrink-0',
                                        item.danger ? 'text-[var(--error)]' : 'text-base-muted'
                                    )}
                                    aria-hidden="true"
                                />
                            )}
                            {item.label}
                        </DropdownMenu.Item>
                    );
                })}
            </DropdownMenu.Content>
        </DropdownMenu.Portal>
    </DropdownMenu.Root>
);

// ── DropdownButton ────────────────────────────────────────────────────────────

export interface DropdownButtonProps {
    children: React.ReactNode;
    items: DropdownItem[];
    variant?: 'primary' | 'secondary' | 'ghost';
    size?: 'sm' | 'md' | 'lg';
    align?: 'left' | 'right';
    disabled?: boolean;
    className?: string;
}

const VARIANT: Record<NonNullable<DropdownButtonProps['variant']>, string> = {
    primary: 'bg-[var(--accent)] text-white hover:bg-[var(--accent-hover)] focus:ring-[var(--accent)]',
    secondary: 'bg-subtle text-base-primary hover:bg-muted focus:ring-[var(--border-strong)]',
    ghost: 'text-base-secondary hover:bg-subtle focus:ring-[var(--border-strong)]',
};

const SIZE_BTN: Record<NonNullable<DropdownButtonProps['size']>, string> = {
    sm: 'px-3 py-1.5 text-sm',
    md: 'px-4 py-2 text-sm',
    lg: 'px-6 py-3 text-base',
};

const DropdownButton: React.FC<DropdownButtonProps> = ({
    children,
    items,
    variant = 'secondary',
    size = 'md',
    align = 'right',
    disabled = false,
    className,
}) => {
    const trigger = (
        <button
            className={cn(
                'inline-flex items-center justify-center font-medium rounded-md',
                'focus:outline-hidden focus:ring-2 focus:ring-offset-2',
                'transition-colors duration-200',
                'disabled:opacity-50 disabled:cursor-not-allowed',
                VARIANT[variant],
                SIZE_BTN[size],
                className
            )}
            disabled={disabled}
        >
            {children}
            <ChevronDownIcon className="ml-2 h-4 w-4" aria-hidden="true" />
        </button>
    );

    return <Dropdown trigger={trigger} items={items} align={align} />;
};

export { Dropdown, DropdownButton };
