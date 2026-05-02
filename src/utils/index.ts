// Utility functions for the application

/**
 * Combines class names conditionally
 */
export function cn(...classes: (string | undefined | null | boolean)[]): string {
    return classes.filter(Boolean).join(' ');
}

/**
 * Formats a date string to a human-readable format
 */
export function formatDate(dateString: string): string {
    const date = new Date(dateString);
    return new Intl.DateTimeFormat('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
    }).format(date);
}

/**
 * Formats a relative time (e.g., "2 hours ago")
 */
export function formatRelativeTime(dateString: string): string {
    const date = new Date(dateString);
    const now = new Date();
    const diffInSeconds = Math.floor((now.getTime() - date.getTime()) / 1000);

    if (diffInSeconds < 60) return 'just now';
    if (diffInSeconds < 3600) return `${Math.floor(diffInSeconds / 60)} minutes ago`;
    if (diffInSeconds < 86400) return `${Math.floor(diffInSeconds / 3600)} hours ago`;
    if (diffInSeconds < 2592000) return `${Math.floor(diffInSeconds / 86400)} days ago`;

    return formatDate(dateString);
}

/**
 * Masks sensitive data for display
 */
export function maskSensitiveData(value: string, visibleChars: number = 4): string {
    if (value.length <= visibleChars) {
        return '*'.repeat(value.length);
    }
    return value.slice(0, visibleChars) + '*'.repeat(value.length - visibleChars);
}

/**
 * Copies text to clipboard and clears it after a timeout
 */
export async function copyToClipboard(text: string, clearTimeout: number = 30000): Promise<void> {
    try {
        await navigator.clipboard.writeText(text);

        // Clear clipboard after timeout
        setTimeout(async () => {
            try {
                await navigator.clipboard.writeText('');
            } catch (error) {
                console.warn('Failed to clear clipboard:', error);
            }
        }, clearTimeout);
    } catch (error) {
        console.error('Failed to copy to clipboard:', error);
        throw new Error('Failed to copy to clipboard');
    }
}

/**
 * Sanitizes user input to prevent XSS
 */
export function sanitizeInput(input: string): string {
    const div = document.createElement('div');
    div.textContent = input;
    return div.innerHTML;
}

/**
 * Validates email format
 */
export function isValidEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

/**
 * Generates a random ID
 */
export function generateId(): string {
    return Math.random().toString(36).substr(2, 9);
}

/**
 * Debounces a function call
 */
export function debounce<T extends (...args: unknown[]) => unknown>(
    func: T,
    wait: number
): (...args: Parameters<T>) => void {
    let timeout: ReturnType<typeof setTimeout>;
    return (...args: Parameters<T>) => {
        clearTimeout(timeout);
        timeout = setTimeout(() => func(...args), wait);
    };
}

/**
 * Throttles a function call
 */
export function throttle<T extends (...args: unknown[]) => unknown>(
    func: T,
    limit: number
): (...args: Parameters<T>) => void {
    let inThrottle: boolean;
    return (...args: Parameters<T>) => {
        if (!inThrottle) {
            func(...args);
            inThrottle = true;
            setTimeout(() => (inThrottle = false), limit);
        }
    };
}

/**
 * Gets environment configuration
 */
export function getEnvConfig() {
    return {
        API_BASE_URL: import.meta.env.VITE_API_BASE_URL || 'http://localhost:8080',
        API_TIMEOUT: parseInt(import.meta.env.VITE_API_TIMEOUT || '30000'),
        APP_NAME: import.meta.env.VITE_APP_NAME || 'Keyorix',
        APP_VERSION: import.meta.env.VITE_APP_VERSION || '1.0.0',
        APP_DESCRIPTION: import.meta.env.VITE_APP_DESCRIPTION || 'Secure Secret Management System',
        ENVIRONMENT: import.meta.env.VITE_ENVIRONMENT || 'development',
        ENABLE_DEBUG: import.meta.env.VITE_ENABLE_DEBUG === 'true',
        ENABLE_DEVTOOLS: import.meta.env.VITE_ENABLE_DEVTOOLS === 'true',
        SESSION_TIMEOUT: parseInt(import.meta.env.VITE_SESSION_TIMEOUT || '3600000'),
        CLIPBOARD_CLEAR_TIMEOUT: parseInt(import.meta.env.VITE_CLIPBOARD_CLEAR_TIMEOUT || '30000'),
        DEFAULT_LANGUAGE: import.meta.env.VITE_DEFAULT_LANGUAGE || 'en',
        DEFAULT_THEME: import.meta.env.VITE_DEFAULT_THEME || 'system',
        ITEMS_PER_PAGE: parseInt(import.meta.env.VITE_ITEMS_PER_PAGE || '20'),
    };
}

/**
 * Storage utilities for localStorage with error handling
 */
export const storage = {
    get: <T>(key: string, defaultValue?: T): T | null => {
        try {
            const item = localStorage.getItem(key);
            return item ? JSON.parse(item) : defaultValue || null;
        } catch (error) {
            console.error(`Error reading from localStorage key "${key}":`, error);
            return defaultValue || null;
        }
    },

    set: <T>(key: string, value: T): void => {
        try {
            localStorage.setItem(key, JSON.stringify(value));
        } catch (error) {
            console.error(`Error writing to localStorage key "${key}":`, error);
        }
    },

    remove: (key: string): void => {
        try {
            localStorage.removeItem(key);
        } catch (error) {
            console.error(`Error removing localStorage key "${key}":`, error);
        }
    },

    clear: (): void => {
        try {
            localStorage.clear();
        } catch (error) {
            console.error('Error clearing localStorage:', error);
        }
    },
};

/**
 * URL utilities
 */
export const url = {
    /**
     * Builds a URL with query parameters
     */
    buildUrl: (base: string, params: Record<string, string | number | boolean>): string => {
        const url = new URL(base, window.location.origin);
        Object.entries(params).forEach(([key, value]) => {
            if (value !== undefined && value !== null) {
                url.searchParams.set(key, String(value));
            }
        });
        return url.toString();
    },

    /**
     * Parses query parameters from current URL
     */
    getQueryParams: (): Record<string, string> => {
        const params = new URLSearchParams(window.location.search);
        const result: Record<string, string> = {};
        params.forEach((value, key) => {
            result[key] = value;
        });
        return result;
    },
};

// Re-export auth utilities
export * from './auth';
// Re-export routing utilities  
export * from './routing';