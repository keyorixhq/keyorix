import React, { useState } from 'react';
import { clsx } from 'clsx';
import { Header } from './Header';
import { Sidebar } from './Sidebar';
import { Footer } from './Footer';
import { Breadcrumb, BreadcrumbItem } from './Breadcrumb';

export interface LayoutProps {
    children: React.ReactNode;
    breadcrumbs?: BreadcrumbItem[];
    showFooter?: boolean;
    className?: string;
}

const Layout: React.FC<LayoutProps> = ({
    children,
    breadcrumbs,
    showFooter = true,
    className,
}) => {
    const [sidebarOpen, setSidebarOpen] = useState(false);

    const handleMenuClick = () => {
        setSidebarOpen(true);
    };

    const handleSidebarClose = () => {
        setSidebarOpen(false);
    };

    return (
        <div className="min-h-screen bg-gray-50">
            {/* Sidebar */}
            <Sidebar isOpen={sidebarOpen} onClose={handleSidebarClose} />

            {/* Main content area */}
            <div className="lg:pl-64 flex flex-col min-h-screen">
                {/* Header */}
                <Header onMenuClick={handleMenuClick} />

                {/* Main content */}
                <main className="flex-1">
                    {/* Breadcrumbs */}
                    {breadcrumbs && breadcrumbs.length > 0 && (
                        <div className="bg-white border-b border-gray-200">
                            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                                <div className="py-4">
                                    <Breadcrumb items={breadcrumbs} />
                                </div>
                            </div>
                        </div>
                    )}

                    {/* Page content */}
                    <div className={clsx('flex-1', className)}>
                        {children}
                    </div>
                </main>

                {/* Footer */}
                {showFooter && <Footer />}
            </div>
        </div>
    );
};

// Simple page wrapper for consistent spacing
export interface PageProps {
    children: React.ReactNode;
    title?: string;
    subtitle?: string;
    actions?: React.ReactNode;
    className?: string;
}

const Page: React.FC<PageProps> = ({
    children,
    title,
    subtitle,
    actions,
    className,
}) => {
    return (
        <div className={clsx('max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8', className)}>
            {(title || subtitle || actions) && (
                <div className="mb-8">
                    <div className="md:flex md:items-center md:justify-between">
                        <div className="flex-1 min-w-0">
                            {title && (
                                <h1 className="text-2xl font-bold leading-7 text-gray-900 sm:text-3xl sm:truncate">
                                    {title}
                                </h1>
                            )}
                            {subtitle && (
                                <p className="mt-1 text-sm text-gray-500">
                                    {subtitle}
                                </p>
                            )}
                        </div>
                        {actions && (
                            <div className="mt-4 flex md:mt-0 md:ml-4">
                                {actions}
                            </div>
                        )}
                    </div>
                </div>
            )}
            {children}
        </div>
    );
};

export { Layout, Page };