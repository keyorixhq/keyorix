import React, { Fragment } from 'react';
import { Menu, Transition } from '@headlessui/react';
import { ChevronDownIcon } from '@heroicons/react/24/outline';
import { clsx } from 'clsx';
import { LucideIcon } from 'lucide-react';

export interface DropdownItem {
    label: string;
    value: string;
    icon?: LucideIcon;
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

const Dropdown: React.FC<DropdownProps> = ({
    trigger,
    items,
    align = 'right',
    className,
}) => {
    const alignmentClasses = {
        left: 'origin-top-left left-0',
        right: 'origin-top-right right-0',
    };

    return (
        <Menu as="div" className={clsx('relative inline-block text-left', className)}>
            <Menu.Button as="div" className="cursor-pointer">
                {trigger}
            </Menu.Button>

            <Transition
                as={Fragment}
                enter="transition ease-out duration-100"
                enterFrom="transform opacity-0 scale-95"
                enterTo="transform opacity-100 scale-100"
                leave="transition ease-in duration-75"
                leaveFrom="transform opacity-100 scale-100"
                leaveTo="transform opacity-0 scale-95"
            >
                <Menu.Items
                    className={clsx(
                        'absolute z-10 mt-2 w-56 rounded-md bg-white shadow-lg ring-1 ring-black ring-opacity-5 focus:outline-none',
                        alignmentClasses[align]
                    )}
                >
                    <div className="py-1">
                        {(items ?? []).map((item) => {
                            const Icon = item.icon;

                            return (
                                <Menu.Item key={item.value} disabled={item.disabled || false}>
                                    {({ active }) => (
                                        <button
                                            className={clsx(
                                                'group flex w-full items-center px-4 py-2 text-sm',
                                                active && !item.disabled && 'bg-gray-100',
                                                item.disabled && 'opacity-50 cursor-not-allowed',
                                                item.danger
                                                    ? 'text-red-700 hover:bg-red-50'
                                                    : 'text-gray-700 hover:bg-gray-100'
                                            )}
                                            onClick={item.onClick}
                                            disabled={item.disabled}
                                        >
                                            {Icon && (
                                                <Icon
                                                    className={clsx(
                                                        'mr-3 h-4 w-4',
                                                        item.danger ? 'text-red-500' : 'text-gray-400'
                                                    )}
                                                    aria-hidden="true"
                                                />
                                            )}
                                            {item.label}
                                        </button>
                                    )}
                                </Menu.Item>
                            );
                        })}
                    </div>
                </Menu.Items>
            </Transition>
        </Menu>
    );
};

// Simple dropdown button component
export interface DropdownButtonProps {
    children: React.ReactNode;
    items: DropdownItem[];
    variant?: 'primary' | 'secondary' | 'ghost';
    size?: 'sm' | 'md' | 'lg';
    align?: 'left' | 'right';
    disabled?: boolean;
    className?: string;
}

const DropdownButton: React.FC<DropdownButtonProps> = ({
    children,
    items,
    variant = 'secondary',
    size = 'md',
    align = 'right',
    disabled = false,
    className,
}) => {
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
        ],
        secondary: [
            'bg-gray-100 text-gray-900 hover:bg-gray-200',
            'focus:ring-gray-500',
        ],
        ghost: [
            'text-gray-700 hover:bg-gray-100',
            'focus:ring-gray-500',
        ],
    };

    const sizeClasses = {
        sm: 'px-3 py-1.5 text-sm',
        md: 'px-4 py-2 text-sm',
        lg: 'px-6 py-3 text-base',
    };

    const trigger = (
        <button
            className={clsx(
                baseClasses,
                variantClasses[variant],
                sizeClasses[size],
                className
            )}
            disabled={disabled}
        >
            {children}
            <ChevronDownIcon className="ml-2 h-4 w-4" aria-hidden="true" />
        </button>
    );

    return (
        <Dropdown
            trigger={trigger}
            items={items}
            align={align}
        />
    );
};

export { Dropdown, DropdownButton };