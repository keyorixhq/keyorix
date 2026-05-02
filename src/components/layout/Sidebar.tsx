import React, { Fragment } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { Dialog, Transition } from '@headlessui/react';
import { clsx } from 'clsx';
import {
    XMarkIcon,
    HomeIcon,
    KeyIcon,
    ShareIcon,
    UserGroupIcon,
    ChartBarIcon,
    Cog6ToothIcon,
    ShieldCheckIcon,
    DocumentTextIcon,
} from '@heroicons/react/24/outline';

export interface NavigationItem {
    name: string;
    href: string;
    icon: React.ComponentType<React.SVGProps<SVGSVGElement>>;
    current?: boolean;
    badge?: number;
    adminOnly?: boolean;
}

export interface SidebarProps {
    isOpen: boolean;
    onClose: () => void;
    className?: string;
}

const Sidebar: React.FC<SidebarProps> = ({ isOpen, onClose, className }) => {
    const location = useLocation();

    const navigation: NavigationItem[] = [
        {
            name: 'Dashboard',
            href: '/dashboard',
            icon: HomeIcon,
        },
        {
            name: 'Secrets',
            href: '/secrets',
            icon: KeyIcon,
        },
        {
            name: 'Shared with me',
            href: '/shared',
            icon: ShareIcon,
        },
        {
            name: 'Groups',
            href: '/groups',
            icon: UserGroupIcon,
        },
        {
            name: 'Analytics',
            href: '/analytics',
            icon: ChartBarIcon,
        },
        {
            name: 'Audit Logs',
            href: '/audit',
            icon: DocumentTextIcon,
        },
    ];

    const adminNavigation: NavigationItem[] = [
        {
            name: 'User Management',
            href: '/admin/users',
            icon: UserGroupIcon,
            adminOnly: true,
        },
        {
            name: 'System Settings',
            href: '/admin/settings',
            icon: Cog6ToothIcon,
            adminOnly: true,
        },
        {
            name: 'Security',
            href: '/admin/security',
            icon: ShieldCheckIcon,
            adminOnly: true,
        },
    ];

    const isCurrentPath = (href: string) => {
        return location.pathname === href || location.pathname.startsWith(href + '/');
    };

    const SidebarContent = () => (
        <div className="flex flex-col h-full">
            {/* Navigation */}
            <nav className="flex-1 px-4 py-6 space-y-1">
                <div className="space-y-1">
                    {navigation.map((item) => {
                        const current = isCurrentPath(item.href);
                        return (
                            <Link
                                key={item.name}
                                to={item.href}
                                className={clsx(
                                    current
                                        ? 'bg-blue-50 border-blue-500 text-blue-700'
                                        : 'border-transparent text-gray-600 hover:bg-gray-50 hover:text-gray-900',
                                    'group flex items-center px-3 py-2 text-sm font-medium border-l-4 transition-colors duration-200'
                                )}
                                onClick={() => onClose()}
                            >
                                <item.icon
                                    className={clsx(
                                        current ? 'text-blue-500' : 'text-gray-400 group-hover:text-gray-500',
                                        'mr-3 h-5 w-5 flex-shrink-0'
                                    )}
                                    aria-hidden="true"
                                />
                                <span className="truncate">{item.name}</span>
                                {item.badge && (
                                    <span className="ml-auto inline-block py-0.5 px-2 text-xs font-medium rounded-full bg-gray-100 text-gray-600">
                                        {item.badge}
                                    </span>
                                )}
                            </Link>
                        );
                    })}
                </div>

                {/* Admin section */}
                <div className="pt-6">
                    <div className="px-3 mb-2">
                        <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider">
                            Administration
                        </h3>
                    </div>
                    <div className="space-y-1">
                        {adminNavigation.map((item) => {
                            const current = isCurrentPath(item.href);
                            return (
                                <Link
                                    key={item.name}
                                    to={item.href}
                                    className={clsx(
                                        current
                                            ? 'bg-blue-50 border-blue-500 text-blue-700'
                                            : 'border-transparent text-gray-600 hover:bg-gray-50 hover:text-gray-900',
                                        'group flex items-center px-3 py-2 text-sm font-medium border-l-4 transition-colors duration-200'
                                    )}
                                    onClick={() => onClose()}
                                >
                                    <item.icon
                                        className={clsx(
                                            current ? 'text-blue-500' : 'text-gray-400 group-hover:text-gray-500',
                                            'mr-3 h-5 w-5 flex-shrink-0'
                                        )}
                                        aria-hidden="true"
                                    />
                                    <span className="truncate">{item.name}</span>
                                </Link>
                            );
                        })}
                    </div>
                </div>
            </nav>

            {/* Footer */}
            <div className="px-4 py-4 border-t border-gray-200">
                <div className="text-xs text-gray-500 text-center">
                    <p>Keyorix v1.0.0</p>
                    <p className="mt-1">
                        <Link to="/help" className="hover:text-gray-700">
                            Help & Support
                        </Link>
                    </p>
                </div>
            </div>
        </div>
    );

    return (
        <>
            {/* Mobile sidebar */}
            <Transition.Root show={isOpen} as={Fragment}>
                <Dialog as="div" className="relative z-40 lg:hidden" onClose={onClose}>
                    <Transition.Child
                        as={Fragment}
                        enter="transition-opacity ease-linear duration-300"
                        enterFrom="opacity-0"
                        enterTo="opacity-100"
                        leave="transition-opacity ease-linear duration-300"
                        leaveFrom="opacity-100"
                        leaveTo="opacity-0"
                    >
                        <div className="fixed inset-0 bg-gray-600 bg-opacity-75" />
                    </Transition.Child>

                    <div className="fixed inset-0 flex z-40">
                        <Transition.Child
                            as={Fragment}
                            enter="transition ease-in-out duration-300 transform"
                            enterFrom="-translate-x-full"
                            enterTo="translate-x-0"
                            leave="transition ease-in-out duration-300 transform"
                            leaveFrom="translate-x-0"
                            leaveTo="-translate-x-full"
                        >
                            <Dialog.Panel className="relative flex-1 flex flex-col max-w-xs w-full bg-white">
                                <Transition.Child
                                    as={Fragment}
                                    enter="ease-in-out duration-300"
                                    enterFrom="opacity-0"
                                    enterTo="opacity-100"
                                    leave="ease-in-out duration-300"
                                    leaveFrom="opacity-100"
                                    leaveTo="opacity-0"
                                >
                                    <div className="absolute top-0 right-0 -mr-12 pt-2">
                                        <button
                                            type="button"
                                            className="ml-1 flex items-center justify-center h-10 w-10 rounded-full focus:outline-none focus:ring-2 focus:ring-inset focus:ring-white"
                                            onClick={onClose}
                                        >
                                            <span className="sr-only">Close sidebar</span>
                                            <XMarkIcon className="h-6 w-6 text-white" aria-hidden="true" />
                                        </button>
                                    </div>
                                </Transition.Child>
                                <SidebarContent />
                            </Dialog.Panel>
                        </Transition.Child>
                        <div className="flex-shrink-0 w-14" aria-hidden="true">
                            {/* Force sidebar to shrink to fit close icon */}
                        </div>
                    </div>
                </Dialog>
            </Transition.Root>

            {/* Desktop sidebar */}
            <div className={clsx('hidden lg:flex lg:flex-col lg:w-64 lg:fixed lg:inset-y-0', className)}>
                <div className="flex flex-col flex-grow bg-white border-r border-gray-200 overflow-y-auto">
                    <SidebarContent />
                </div>
            </div>
        </>
    );
};

export { Sidebar };