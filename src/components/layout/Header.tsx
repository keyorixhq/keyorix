import React from 'react';
import { useNavigate } from 'react-router-dom';
import { clsx } from 'clsx';
import {
    Bars3Icon,
    BellIcon,
    UserCircleIcon,
    ArrowRightOnRectangleIcon,
    SunIcon,
    MoonIcon,
    ComputerDesktopIcon,
} from '@heroicons/react/24/outline';
import { Dropdown, DropdownItem } from '../ui/Dropdown';

import { useAuth } from '../../features/auth';
import { useUIStore } from '../../store/uiStore';

export interface HeaderProps {
    onMenuClick: () => void;
    className?: string;
}

const Header: React.FC<HeaderProps> = ({ onMenuClick, className }) => {
    const { user, logout } = useAuth();
    const navigate = useNavigate();
    const { theme, setTheme } = useUIStore();

    const handleLogout = async () => {
        try {
            await logout();
            navigate('/login');
        } catch (error) {
            console.error('Logout failed:', error);
        }
    };

    const userMenuItems: DropdownItem[] = [
        {
            label: 'Sign out',
            value: 'logout',
            icon: ArrowRightOnRectangleIcon,
            onClick: handleLogout,
            danger: true,
        },
    ];

    const userMenuTrigger = (
        <button className="flex items-center space-x-2 text-sm rounded-full focus:outline-hidden focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 p-1">
            <div className="h-8 w-8 rounded-full flex items-center justify-center" style={{ backgroundColor: 'var(--bg-muted)' }}>
                <UserCircleIcon className="h-6 w-6" style={{ color: 'var(--text-secondary)' }} />
            </div>
            <span className="hidden md:block font-medium" style={{ color: 'var(--text-secondary)' }}>
                {user?.displayName || user?.username || 'User'}
            </span>
        </button>
    );

    return (
        <header
            className={clsx('shadow-xs border-b', className)}
            style={{ backgroundColor: 'var(--bg-surface)', borderColor: 'var(--border)' }}
        >
            <div className="px-4 sm:px-6 lg:px-8">
                <div className="flex justify-between items-center h-16">
                    {/* Left — mobile menu button */}
                    <div className="flex items-center">
                        <button
                            type="button"
                            className="p-2 rounded-md focus:outline-hidden focus:ring-2 focus:ring-inset focus:ring-blue-500 lg:hidden"
                            style={{ color: 'var(--text-muted)' }}
                            onClick={onMenuClick}
                        >
                            <span className="sr-only">Open sidebar</span>
                            <Bars3Icon className="h-6 w-6" aria-hidden="true" />
                        </button>
                    </div>

                    {/* Right — theme toggle + notifications + user menu */}
                    <div className="flex items-center space-x-2">
                        {/* Notifications — coming soon, intentionally inert */}
                        <div
                            className="p-2 rounded-md relative"
                            style={{ color: 'var(--text-muted)', opacity: 0.35, cursor: 'default' }}
                            title="Notifications — coming soon"
                            aria-hidden="true"
                        >
                            <BellIcon className="h-6 w-6" />
                        </div>

                        {/* Theme toggle — cycles dark → light → system */}
                        <button
                            type="button"
                            onClick={() => setTheme(theme === 'dark' ? 'light' : theme === 'light' ? 'system' : 'dark')}
                            className="p-2 rounded-md transition-colors focus:outline-hidden focus:ring-2 focus:ring-inset focus:ring-blue-500"
                            style={{ color: 'var(--text-muted)' }}
                            title={theme === 'dark' ? 'Dark mode (click for light)' : theme === 'light' ? 'Light mode (click for system)' : 'System mode (click for dark)'}
                            aria-label={theme === 'dark' ? 'Dark mode' : theme === 'light' ? 'Light mode' : 'System mode'}
                        >
                            {theme === 'dark'
                                ? <MoonIcon className="h-5 w-5" aria-hidden="true" />
                                : theme === 'light'
                                    ? <SunIcon className="h-5 w-5" aria-hidden="true" />
                                    : <ComputerDesktopIcon className="h-5 w-5" aria-hidden="true" />
                            }
                        </button>

                        {/* User menu */}
                        <Dropdown
                            trigger={userMenuTrigger}
                            items={userMenuItems}
                            align="right"
                        />
                    </div>
                </div>
            </div>
        </header>
    );
};

export { Header };
