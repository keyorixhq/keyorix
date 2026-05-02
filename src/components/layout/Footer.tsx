import React from 'react';
import { Link } from 'react-router-dom';
import { clsx } from 'clsx';

export interface FooterProps {
    className?: string;
}

const Footer: React.FC<FooterProps> = ({ className }) => {
    const currentYear = new Date().getFullYear();

    const footerLinks = [
        { name: 'Documentation', href: '/docs' },
        { name: 'API Reference', href: '/api-docs' },
        { name: 'Support', href: '/support' },
        { name: 'Privacy Policy', href: '/privacy' },
        { name: 'Terms of Service', href: '/terms' },
    ];

    return (
        <footer className={clsx(
            'bg-white border-t border-gray-200',
            className
        )}>
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                <div className="py-8">
                    <div className="md:flex md:items-center md:justify-between">
                        {/* Left side - Logo and description */}
                        <div className="flex items-center space-x-4">
                            <div className="h-8 w-8 bg-blue-600 rounded-lg flex items-center justify-center">
                                <span className="text-white font-bold text-sm">S</span>
                            </div>
                            <div>
                                <h3 className="text-sm font-semibold text-gray-900">Keyorix</h3>
                                <p className="text-xs text-gray-500">Secure secret management</p>
                            </div>
                        </div>

                        {/* Right side - Links */}
                        <div className="mt-4 md:mt-0">
                            <div className="flex flex-wrap items-center space-x-6">
                                {footerLinks.map((link) => (
                                    <Link
                                        key={link.name}
                                        to={link.href}
                                        className="text-sm text-gray-500 hover:text-gray-700 transition-colors duration-200"
                                    >
                                        {link.name}
                                    </Link>
                                ))}
                            </div>
                        </div>
                    </div>

                    {/* Bottom section */}
                    <div className="mt-8 pt-8 border-t border-gray-200">
                        <div className="md:flex md:items-center md:justify-between">
                            <div className="flex items-center space-x-6 text-sm text-gray-500">
                                <span>Version 1.0.0</span>
                                <span>•</span>
                                <span>Build {import.meta.env.VITE_BUILD_NUMBER || 'dev'}</span>
                                <span>•</span>
                                <span>
                                    Status:
                                    <span className="ml-1 inline-flex items-center">
                                        <span className="h-2 w-2 bg-green-400 rounded-full mr-1"></span>
                                        Operational
                                    </span>
                                </span>
                            </div>

                            <div className="mt-4 md:mt-0">
                                <p className="text-sm text-gray-500">
                                    © {currentYear} Keyorix. All rights reserved.
                                </p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </footer>
    );
};

export { Footer };