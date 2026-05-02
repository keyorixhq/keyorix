import React from 'react';
import { Link } from 'react-router-dom';
import { ChevronRightIcon, HomeIcon } from '@heroicons/react/24/outline';
import { clsx } from 'clsx';

export interface BreadcrumbItem {
    name: string;
    href?: string;
    current?: boolean;
}

export interface BreadcrumbProps {
    items: BreadcrumbItem[];
    className?: string;
}

const Breadcrumb: React.FC<BreadcrumbProps> = ({ items, className }) => {
    return (
        <nav className={clsx('flex', className)} aria-label="Breadcrumb">
            <ol className="flex items-center space-x-2">
                {/* Home icon */}
                <li>
                    <div>
                        <Link
                            to="/dashboard"
                            className="text-gray-400 hover:text-gray-500 transition-colors duration-200"
                        >
                            <HomeIcon className="h-5 w-5 flex-shrink-0" aria-hidden="true" />
                            <span className="sr-only">Home</span>
                        </Link>
                    </div>
                </li>

                {items.map((item) => (
                    <li key={item.name}>
                        <div className="flex items-center">
                            <ChevronRightIcon
                                className="h-5 w-5 flex-shrink-0 text-gray-400"
                                aria-hidden="true"
                            />
                            {item.href && !item.current ? (
                                <Link
                                    to={item.href}
                                    className="ml-2 text-sm font-medium text-gray-500 hover:text-gray-700 transition-colors duration-200"
                                    aria-current={item.current ? 'page' : undefined}
                                >
                                    {item.name}
                                </Link>
                            ) : (
                                <span
                                    className={clsx(
                                        'ml-2 text-sm font-medium',
                                        item.current
                                            ? 'text-gray-900'
                                            : 'text-gray-500'
                                    )}
                                    aria-current={item.current ? 'page' : undefined}
                                >
                                    {item.name}
                                </span>
                            )}
                        </div>
                    </li>
                ))}
            </ol>
        </nav>
    );
};

export { Breadcrumb };