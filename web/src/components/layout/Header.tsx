import React from 'react';
import { useNavigate } from 'react-router';
import { clsx } from 'clsx';
import {
    Bars3Icon,
    UserCircleIcon,
    ArrowRightStartOnRectangleIcon,
    Cog6ToothIcon,
} from '@heroicons/react/24/outline';
import { Dropdown, DropdownItem } from '../ui/Dropdown';

import { useAuth } from '../../features/auth';
import { userOwesMfaEnrolment } from '../../features/auth/setup';
import { NotificationBell } from '../../features/notifications';
import { ThemeSwitch } from './ThemeSwitch';
import { ROUTES } from '../../constants';

export interface HeaderProps {
    onMenuClick: () => void;
    className?: string;
}

const Header: React.FC<HeaderProps> = ({ onMenuClick, className }) => {
    const { user, logout } = useAuth();
    const navigate = useNavigate();
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
            label: 'My Account',
            value: 'account',
            icon: UserCircleIcon,
            onClick: () => navigate(ROUTES.PROFILE),
        },
        {
            label: 'Sign out',
            value: 'logout',
            icon: ArrowRightStartOnRectangleIcon,
            onClick: handleLogout,
            danger: true,
        },
    ];

    const userMenuTrigger = (
        <button
            type="button"
            data-testid="user-menu-button"
            className="flex items-center space-x-2 text-sm rounded-full focus:outline-hidden focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 p-1"
        >
            <div
                className="h-8 w-8 rounded-full flex items-center justify-center"
                style={{ backgroundColor: 'var(--bg-muted)' }}
            >
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

                    {/* Right — notifications + theme + settings + user menu */}
                    <div className="flex items-center space-x-2">
                        {/* Notifications (ADR-024) — unread badge + dropdown. */}
                        {/* Not under the MFA-enrolment confinement (#3155): its poll would 403. */}
                        {!userOwesMfaEnrolment(user) && <NotificationBell />}

                        {/* Theme: all three positions visible at once (light, system, dark) */}
                        <ThemeSwitch />

                        {/* Settings: always visible, not hidden in a menu */}
                        <button
                            type="button"
                            data-testid="settings-button"
                            onClick={() => navigate(ROUTES.SETTINGS_APPEARANCE)}
                            className="p-2 rounded-full transition-colors focus:outline-hidden focus-visible:ring-2 focus-visible:ring-blue-500"
                            style={{ color: 'var(--text-secondary)' }}
                            title="Settings"
                            aria-label="Settings"
                        >
                            <Cog6ToothIcon className="h-6 w-6" aria-hidden="true" />
                        </button>

                        {/* User menu */}
                        <Dropdown trigger={userMenuTrigger} items={userMenuItems} align="right" />
                    </div>
                </div>
            </div>
        </header>
    );
};

export { Header };
