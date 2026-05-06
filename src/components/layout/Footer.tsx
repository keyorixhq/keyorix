import React from 'react';
import { clsx } from 'clsx';

export interface FooterProps {
    className?: string;
}

const Footer: React.FC<FooterProps> = ({ className }) => {
    return (
        <footer className={clsx('bg-white border-t border-gray-200', className)}>
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
                <p className="text-xs text-gray-400 text-center">
                    Keyorix v0.1.0
                </p>
            </div>
        </footer>
    );
};

export { Footer };
