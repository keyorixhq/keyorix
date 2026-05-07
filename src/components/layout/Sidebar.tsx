import React, { Fragment } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { Dialog, Transition } from '@headlessui/react';
import { clsx } from 'clsx';
import {
    XMarkIcon,
    HomeIcon,
    KeyIcon,
    FolderIcon,
    DocumentTextIcon,
    ChevronDownIcon,
    ShieldCheckIcon,
    Cog6ToothIcon,
    PuzzlePieceIcon,
    ScaleIcon,
} from '@heroicons/react/24/outline';
import { useUIStore } from '../../store/uiStore';

export interface SidebarProps {
    isOpen: boolean;
    onClose: () => void;
    className?: string;
}

interface NavLeaf {
    kind: 'leaf';
    name: string;
    href: string;
    icon?: React.ComponentType<React.SVGProps<SVGSVGElement>>;
    soon?: boolean;
}

interface NavGroup {
    kind: 'group';
    id: string;
    name: string;
    icon: React.ComponentType<React.SVGProps<SVGSVGElement>>;
    children: NavLeaf[];
}

type NavItem = NavLeaf | NavGroup;

const NAV: NavItem[] = [
    {
        kind: 'leaf',
        name: 'Dashboard',
        href: '/dashboard',
        icon: HomeIcon,
    },
    {
        kind: 'leaf',
        name: 'Projects',
        href: '/projects',
        icon: FolderIcon,
    },
    {
        kind: 'group',
        id: 'secrets',
        name: 'Secrets',
        icon: KeyIcon,
        children: [
            { kind: 'leaf', name: 'All Secrets', href: '/secrets' },
            { kind: 'leaf', name: 'Rotation Policies', href: '/secrets/rotation', soon: true },
            { kind: 'leaf', name: 'Dynamic Secrets', href: '/secrets/dynamic', soon: true },
        ],
    },
    {
        kind: 'leaf',
        name: 'Audit Logs',
        href: '/audit',
        icon: DocumentTextIcon,
    },
    {
        kind: 'group',
        id: 'access',
        name: 'Access Control',
        icon: ShieldCheckIcon,
        children: [
            { kind: 'leaf', name: 'Users', href: '/admin/users' },
            { kind: 'leaf', name: 'Groups', href: '/admin/groups', soon: true },
            { kind: 'leaf', name: 'Roles & Policies', href: '/admin/roles', soon: true },
            { kind: 'leaf', name: 'Service Accounts', href: '/admin/service-accounts', soon: true },
            { kind: 'leaf', name: 'API Tokens', href: '/admin/tokens', soon: true },
        ],
    },
    {
        kind: 'group',
        id: 'integrations',
        name: 'Integrations',
        icon: PuzzlePieceIcon,
        children: [
            { kind: 'leaf', name: 'SDKs & CLI', href: '/integrations/sdks', soon: true },
            { kind: 'leaf', name: 'Keyorix Connect', href: '/integrations/connect', soon: true },
            { kind: 'leaf', name: 'Webhooks', href: '/integrations/webhooks', soon: true },
        ],
    },
    {
        kind: 'leaf',
        name: 'Compliance',
        href: '/compliance',
        icon: ScaleIcon,
        soon: true,
    },
    {
        kind: 'group',
        id: 'settings',
        name: 'Settings',
        icon: Cog6ToothIcon,
        children: [
            { kind: 'leaf', name: 'Appearance', href: '/settings/appearance' },
            { kind: 'leaf', name: 'Authentication', href: '/settings/auth', soon: true },
            { kind: 'leaf', name: 'Encryption & Keys', href: '/settings/encryption', soon: true },
            { kind: 'leaf', name: 'System Health', href: '/settings/health', soon: true },
        ],
    },
];

const Sidebar: React.FC<SidebarProps> = ({ isOpen, onClose, className }) => {
    const location = useLocation();
    const { sidebarExpanded, toggleSidebarGroup } = useUIStore();

    const isActive = (href: string) =>
        location.pathname === href || location.pathname.startsWith(href + '/');

    const isGroupActive = (group: NavGroup) =>
        group.children.some(c => isActive(c.href));

    // ── Leaf link ────────────────────────────────────────────────────────────
    const Leaf: React.FC<{ item: NavLeaf; indent?: boolean }> = ({ item, indent }) => {
        const active = isActive(item.href);
        return (
            <Link
                to={item.soon ? '#' : item.href}
                onClick={item.soon ? (e) => e.preventDefault() : onClose}
                className={clsx(
                    'group flex items-center justify-between px-3 py-1.5 text-sm rounded-md transition-colors duration-100',
                    indent ? 'ml-6' : '',
                    active
                        ? 'font-medium'
                        : 'font-normal',
                    item.soon && 'cursor-default'
                )}
                style={{
                    backgroundColor: active ? 'var(--accent-subtle)' : undefined,
                    color: active ? 'var(--accent-text)' : item.soon ? 'var(--text-muted)' : 'var(--text-secondary)',
                }}
                onMouseEnter={e => {
                    if (!active && !item.soon)
                        (e.currentTarget as HTMLElement).style.backgroundColor = 'var(--bg-subtle)';
                }}
                onMouseLeave={e => {
                    if (!active)
                        (e.currentTarget as HTMLElement).style.backgroundColor = '';
                }}
            >
                <span className="flex items-center gap-2.5 truncate">
                    {item.icon && (
                        <item.icon className="h-4 w-4 flex-shrink-0"
                            style={{ color: active ? 'var(--accent)' : 'var(--text-muted)' }} />
                    )}
                    {item.name}
                </span>
                {item.soon && (
                    <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded uppercase tracking-wide flex-shrink-0"
                        style={{ backgroundColor: 'var(--bg-muted)', color: 'var(--text-muted)' }}>
                        Soon
                    </span>
                )}
            </Link>
        );
    };

    // ── Group row ────────────────────────────────────────────────────────────
    const Group: React.FC<{ item: NavGroup }> = ({ item }) => {
        const expanded = sidebarExpanded[item.id] ?? false;
        const active = isGroupActive(item);
        return (
            <div>
                <button
                    type="button"
                    onClick={() => toggleSidebarGroup(item.id)}
                    className="w-full flex items-center justify-between px-3 py-1.5 text-sm rounded-md transition-colors duration-100"
                    style={{
                        color: active ? 'var(--text-primary)' : 'var(--text-secondary)',
                        fontWeight: active ? 500 : 400,
                    }}
                    onMouseEnter={e => (e.currentTarget as HTMLElement).style.backgroundColor = 'var(--bg-subtle)'}
                    onMouseLeave={e => (e.currentTarget as HTMLElement).style.backgroundColor = ''}
                >
                    <span className="flex items-center gap-2.5">
                        <item.icon className="h-4 w-4 flex-shrink-0"
                            style={{ color: active ? 'var(--accent)' : 'var(--text-muted)' }} />
                        {item.name}
                    </span>
                    <ChevronDownIcon
                        className={clsx('h-3.5 w-3.5 flex-shrink-0 transition-transform duration-200',
                            expanded && 'rotate-180')}
                        style={{ color: 'var(--text-muted)' }}
                    />
                </button>
                {expanded && (
                    <div className="mt-0.5 space-y-0.5">
                        {item.children.map(child => (
                            <Leaf key={child.href} item={child} indent />
                        ))}
                    </div>
                )}
            </div>
        );
    };

    // ── Sidebar content ──────────────────────────────────────────────────────
    const SidebarContent = () => (
        <div className="flex flex-col h-full" style={{ backgroundColor: 'var(--bg-surface)' }}>
            {/* Logo */}
            <div className="flex items-center px-5 py-5 border-b flex-shrink-0"
                style={{ borderColor: 'var(--border)' }}>
                <Link to="/dashboard" className="flex items-center space-x-2" onClick={onClose}>
                    <div className="h-8 w-8 bg-blue-600 rounded-lg flex items-center justify-center flex-shrink-0">
                        <span className="text-white font-bold text-sm">K</span>
                    </div>
                    <span className="text-xl font-semibold" style={{ color: 'var(--text-primary)' }}>
                        Keyorix
                    </span>
                </Link>
            </div>

            {/* Nav */}
            <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-0.5">
                {NAV.map(item =>
                    item.kind === 'leaf'
                        ? <Leaf key={item.href} item={item} />
                        : <Group key={item.id} item={item} />
                )}
            </nav>

            {/* Footer */}
            <div className="px-4 py-3 border-t flex-shrink-0"
                style={{ borderColor: 'var(--border)' }}>
                <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Keyorix v0.1.0</p>
            </div>
        </div>
    );

    return (
        <>
            {/* Mobile */}
            <Transition.Root show={isOpen} as={Fragment}>
                <Dialog as="div" className="relative z-40 lg:hidden" onClose={onClose}>
                    <Transition.Child as={Fragment}
                        enter="transition-opacity ease-linear duration-300" enterFrom="opacity-0" enterTo="opacity-100"
                        leave="transition-opacity ease-linear duration-300" leaveFrom="opacity-100" leaveTo="opacity-0">
                        <div className="fixed inset-0 bg-black bg-opacity-60" />
                    </Transition.Child>
                    <div className="fixed inset-0 flex z-40">
                        <Transition.Child as={Fragment}
                            enter="transition ease-in-out duration-300 transform" enterFrom="-translate-x-full" enterTo="translate-x-0"
                            leave="transition ease-in-out duration-300 transform" leaveFrom="translate-x-0" leaveTo="-translate-x-full">
                            <Dialog.Panel className="relative flex-1 flex flex-col max-w-xs w-full"
                                style={{ backgroundColor: 'var(--bg-surface)' }}>
                                <div className="absolute top-0 right-0 -mr-12 pt-2">
                                    <button type="button" onClick={onClose}
                                        className="ml-1 flex items-center justify-center h-10 w-10 rounded-full focus:outline-none focus:ring-2 focus:ring-inset focus:ring-white">
                                        <XMarkIcon className="h-6 w-6 text-white" />
                                    </button>
                                </div>
                                <SidebarContent />
                            </Dialog.Panel>
                        </Transition.Child>
                        <div className="flex-shrink-0 w-14" aria-hidden="true" />
                    </div>
                </Dialog>
            </Transition.Root>

            {/* Desktop */}
            <div className={clsx('hidden lg:flex lg:flex-col lg:w-64 lg:fixed lg:inset-y-0', className)}>
                <div className="flex flex-col flex-grow border-r overflow-y-auto"
                    style={{ backgroundColor: 'var(--bg-surface)', borderColor: 'var(--border)' }}>
                    <SidebarContent />
                </div>
            </div>
        </>
    );
};

export { Sidebar };
