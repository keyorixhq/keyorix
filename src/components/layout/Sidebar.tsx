import React, { Fragment } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { Dialog, Transition } from '@headlessui/react';
import { clsx } from 'clsx';
import {
    XMarkIcon,
    HomeIcon,
    KeyIcon,
    UserGroupIcon,
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
        { name: 'Dashboard',    href: '/dashboard', icon: HomeIcon },
        { name: 'Secrets',      href: '/secrets',   icon: KeyIcon },
        { name: 'Audit Logs',   href: '/audit',     icon: DocumentTextIcon },
    ];

    const adminNavigation: NavigationItem[] = [
        { name: 'User Management', href: '/admin/users', icon: UserGroupIcon, adminOnly: true },
    ];

    const isCurrentPath = (href: string) =>
        location.pathname === href || location.pathname.startsWith(href + '/');

    const NavLink: React.FC<{ item: NavigationItem }> = ({ item }) => {
        const current = isCurrentPath(item.href);
        return (
            <Link
                to={item.href}
                className={clsx(
                    'group flex items-center px-3 py-2 text-sm font-medium border-l-4 transition-colors duration-150',
                    current ? 'border-blue-500' : 'border-transparent'
                )}
                style={{
                    backgroundColor: current ? 'var(--accent-subtle)' : undefined,
                    color: current ? 'var(--accent-text)' : 'var(--text-secondary)',
                }}
                onMouseEnter={(e) => {
                    if (!current) {
                        (e.currentTarget as HTMLElement).style.backgroundColor = 'var(--bg-subtle)';
                        (e.currentTarget as HTMLElement).style.color = 'var(--text-primary)';
                    }
                }}
                onMouseLeave={(e) => {
                    if (!current) {
                        (e.currentTarget as HTMLElement).style.backgroundColor = '';
                        (e.currentTarget as HTMLElement).style.color = 'var(--text-secondary)';
                    }
                }}
                onClick={() => onClose()}
            >
                <item.icon
                    className="mr-3 h-5 w-5 flex-shrink-0"
                    style={{ color: current ? 'var(--accent)' : 'var(--text-muted)' }}
                    aria-hidden="true"
                />
                <span className="truncate">{item.name}</span>
                {item.badge != null && (
                    <span
                        className="ml-auto inline-block py-0.5 px-2 text-xs font-medium rounded-full"
                        style={{ backgroundColor: 'var(--bg-muted)', color: 'var(--text-secondary)' }}
                    >
                        {item.badge}
                    </span>
                )}
            </Link>
        );
    };

    const SidebarContent = () => (
        <div className="flex flex-col h-full" style={{ backgroundColor: 'var(--bg-surface)' }}>
            {/* Logo */}
            <div className="flex items-center px-5 py-5 border-b" style={{ borderColor: 'var(--border)' }}>
                <Link to="/dashboard" className="flex items-center space-x-2" onClick={() => onClose()}>
                    <div className="h-8 w-8 bg-blue-600 rounded-lg flex items-center justify-center flex-shrink-0">
                        <span className="text-white font-bold text-sm">K</span>
                    </div>
                    <span className="text-xl font-semibold" style={{ color: 'var(--text-primary)' }}>
                        Keyorix
                    </span>
                </Link>
            </div>

            {/* Navigation */}
            <nav className="flex-1 px-4 py-6 space-y-1">
                <div className="space-y-1">
                    {navigation.map((item) => <NavLink key={item.name} item={item} />)}
                </div>

                {/* Admin section */}
                <div className="pt-6">
                    <div className="px-3 mb-2">
                        <h3 className="text-xs font-semibold uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>
                            Administration
                        </h3>
                    </div>
                    <div className="space-y-1">
                        {adminNavigation.map((item) => <NavLink key={item.name} item={item} />)}
                    </div>
                </div>
            </nav>
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
                            <Dialog.Panel className="relative flex-1 flex flex-col max-w-xs w-full" style={{ backgroundColor: 'var(--bg-surface)' }}>
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
                        <div className="flex-shrink-0 w-14" aria-hidden="true" />
                    </div>
                </Dialog>
            </Transition.Root>

            {/* Desktop sidebar */}
            <div className={clsx('hidden lg:flex lg:flex-col lg:w-64 lg:fixed lg:inset-y-0', className)}>
                <div
                    className="flex flex-col flex-grow border-r overflow-y-auto"
                    style={{ backgroundColor: 'var(--bg-surface)', borderColor: 'var(--border)' }}
                >
                    <SidebarContent />
                </div>
            </div>
        </>
    );
};

export { Sidebar };
