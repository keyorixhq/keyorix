import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { clsx } from 'clsx';
import {
    Bars3Icon,
    BellIcon,
    MagnifyingGlassIcon,
    UserCircleIcon,
    Cog6ToothIcon,
    ArrowRightOnRectangleIcon
} from '@heroicons/react/24/outline';
import { Dropdown, DropdownItem } from '../ui/Dropdown';

import { useAuth } from '../../hooks/useAuth';

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
            label: 'Profile',
            value: 'profile',
            icon: UserCircleIcon,
            onClick: () => navigate('/profile'),
        },
        {
            label: 'Settings',
            value: 'settings',
            icon: Cog6ToothIcon,
            onClick: () => navigate('/settings'),
        },
        {
            label: 'Sign out',
            value: 'logout',
            icon: ArrowRightOnRectangleIcon,
            onClick: handleLogout,
            danger: true,
        },
    ];

    const userMenuTrigger = (
        <button className="flex items-center space-x-2 text-sm rounded-full focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 p-1">
            <div className="h-8 w-8 rounded-full bg-gray-300 flex items-center justify-center">
                <UserCircleIcon className="h-6 w-6 text-gray-600" />
            </div>
            <span className="hidden md:block text-gray-700 font-medium">
                {user?.username || 'User'}
            </span>
        </button>
    );

    return (
        <header className={clsx(
            'bg-white shadow-sm border-b border-gray-200',
            className
        )}>
            <div className="px-4 sm:px-6 lg:px-8">
                <div className="flex justify-between items-center h-16">
                    {/* Left side - Menu button and logo */}
                    <div className="flex items-center space-x-4">
                        <button
                            type="button"
                            className="p-2 rounded-md text-gray-400 hover:text-gray-500 hover:bg-gray-100 focus:outline-none focus:ring-2 focus:ring-inset focus:ring-blue-500 lg:hidden"
                            onClick={onMenuClick}
                        >
                            <span className="sr-only">Open sidebar</span>
                            <Bars3Icon className="h-6 w-6" aria-hidden="true" />
                        </button>

                        <Link to="/dashboard" className="flex items-center space-x-2">
                            <div className="h-8 w-8 bg-blue-600 rounded-lg flex items-center justify-center">
                                <span className="text-white font-bold text-sm">S</span>
                            </div>
                            <span className="hidden sm:block text-xl font-semibold text-gray-900">
                                Keyorix
                            </span>
                        </Link>
                    </div>

                    {/* Center - Search bar (hidden on mobile) */}
                    <div className="hidden md:flex flex-1 max-w-lg mx-8">
                        <div className="relative w-full">
                            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                <MagnifyingGlassIcon className="h-5 w-5 text-gray-400" aria-hidden="true" />
                            </div>
                            <input
                                type="text"
                                className="block w-full pl-10 pr-3 py-2 border border-gray-300 rounded-md leading-5 bg-white placeholder-gray-500 focus:outline-none focus:placeholder-gray-400 focus:ring-1 focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                                placeholder="Search secrets, users, groups..."
                            />
                        </div>
                    </div>

                    {/* Right side - Notifications and user menu */}
                    <div className="flex items-center space-x-4">
                        {/* Search button for mobile */}
                        <button
                            type="button"
                            className="p-2 rounded-md text-gray-400 hover:text-gray-500 hover:bg-gray-100 focus:outline-none focus:ring-2 focus:ring-inset focus:ring-blue-500 md:hidden"
                        >
                            <span className="sr-only">Search</span>
                            <MagnifyingGlassIcon className="h-6 w-6" aria-hidden="true" />
                        </button>

                        {/* Notifications */}
                        <button
                            type="button"
                            className="p-2 rounded-md text-gray-400 hover:text-gray-500 hover:bg-gray-100 focus:outline-none focus:ring-2 focus:ring-inset focus:ring-blue-500 relative"
                        >
                            <span className="sr-only">View notifications</span>
                            <BellIcon className="h-6 w-6" aria-hidden="true" />
                            {/* Notification badge */}
                            <span className="absolute top-1 right-1 block h-2 w-2 rounded-full bg-red-400 ring-2 ring-white" />
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