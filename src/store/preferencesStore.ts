import React from 'react';
import { create } from 'zustand';
import { devtools, persist } from 'zustand/middleware';
import { UserPreferences, NotificationSettings } from '../types';

interface PreferencesState extends UserPreferences {
    // Additional UI preferences not in UserPreferences
    sidebarCollapsed: boolean;
    compactMode: boolean;
    showTooltips: boolean;
    autoSave: boolean;
    confirmDeletion: boolean;

    // Session preferences (not persisted)
    sessionTimeout: number;
    clipboardTimeout: number;

    // Actions
    setLanguage: (language: string) => void;
    setTimezone: (timezone: string) => void;
    setTheme: (theme: 'light' | 'dark' | 'system') => void;
    setNotificationSettings: (settings: Partial<NotificationSettings>) => void;
    setSidebarCollapsed: (collapsed: boolean) => void;
    setCompactMode: (compact: boolean) => void;
    setShowTooltips: (show: boolean) => void;
    setAutoSave: (autoSave: boolean) => void;
    setConfirmDeletion: (confirm: boolean) => void;
    setSessionTimeout: (timeout: number) => void;
    setClipboardTimeout: (timeout: number) => void;

    // Bulk operations
    updatePreferences: (preferences: Partial<UserPreferences>) => void;
    resetToDefaults: () => void;

    // Getters
    getFormattedDate: (date: string | Date) => string;
    getFormattedTime: (date: string | Date) => string;
    isRTL: () => boolean;
}

const defaultPreferences: UserPreferences = {
    language: 'en',
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    theme: 'system',
    notifications: {
        email: true,
        browser: true,
        sharing: true,
        security: true,
    },
};

const defaultUIPreferences = {
    sidebarCollapsed: false,
    compactMode: false,
    showTooltips: true,
    autoSave: true,
    confirmDeletion: true,
    sessionTimeout: 30 * 60 * 1000, // 30 minutes
    clipboardTimeout: 30 * 1000, // 30 seconds
};

export const usePreferencesStore = create<PreferencesState>()(
    devtools(
        persist(
            (set, get) => ({
                ...defaultPreferences,
                ...defaultUIPreferences,

                setLanguage: (language) => {
                    set({ language });

                    // Update document language
                    document.documentElement.lang = language;

                    // Update document direction for RTL languages
                    const rtlLanguages = ['ar', 'he', 'fa', 'ur'];
                    document.documentElement.dir = rtlLanguages.includes(language) ? 'rtl' : 'ltr';
                },

                setTimezone: (timezone) => {
                    set({ timezone });
                },

                setTheme: (theme) => {
                    set({ theme });

                    // Apply theme to document
                    const root = document.documentElement;
                    if (theme === 'dark') {
                        root.classList.add('dark');
                    } else if (theme === 'light') {
                        root.classList.remove('dark');
                    } else {
                        // System theme
                        const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
                        if (prefersDark) {
                            root.classList.add('dark');
                        } else {
                            root.classList.remove('dark');
                        }
                    }
                },

                setNotificationSettings: (settings) => {
                    set((state) => ({
                        notifications: {
                            ...state.notifications,
                            ...settings,
                        },
                    }));
                },

                setSidebarCollapsed: (collapsed) => {
                    set({ sidebarCollapsed: collapsed });
                },

                setCompactMode: (compact) => {
                    set({ compactMode: compact });
                },

                setShowTooltips: (show) => {
                    set({ showTooltips: show });
                },

                setAutoSave: (autoSave) => {
                    set({ autoSave });
                },

                setConfirmDeletion: (confirm) => {
                    set({ confirmDeletion: confirm });
                },

                setSessionTimeout: (timeout) => {
                    set({ sessionTimeout: timeout });
                },

                setClipboardTimeout: (timeout) => {
                    set({ clipboardTimeout: timeout });
                },

                updatePreferences: (preferences) => {
                    set((state) => ({
                        ...state,
                        ...preferences,
                    }));
                },

                resetToDefaults: () => {
                    set({
                        ...defaultPreferences,
                        ...defaultUIPreferences,
                    });

                    // Reset document attributes
                    document.documentElement.lang = defaultPreferences.language;
                    document.documentElement.dir = 'ltr';
                    document.documentElement.classList.remove('dark');
                },

                getFormattedDate: (date) => {
                    const { timezone, language } = get();
                    const dateObj = typeof date === 'string' ? new Date(date) : date;

                    return new Intl.DateTimeFormat(language, {
                        timeZone: timezone,
                        year: 'numeric',
                        month: 'short',
                        day: 'numeric',
                    }).format(dateObj);
                },

                getFormattedTime: (date) => {
                    const { timezone, language } = get();
                    const dateObj = typeof date === 'string' ? new Date(date) : date;

                    return new Intl.DateTimeFormat(language, {
                        timeZone: timezone,
                        hour: '2-digit',
                        minute: '2-digit',
                    }).format(dateObj);
                },

                isRTL: () => {
                    const { language } = get();
                    const rtlLanguages = ['ar', 'he', 'fa', 'ur'];
                    return rtlLanguages.includes(language);
                },
            }),
            {
                name: 'preferences-store',
                partialize: (state) => ({
                    // Persist user preferences
                    language: state.language,
                    timezone: state.timezone,
                    theme: state.theme,
                    notifications: state.notifications,
                    sidebarCollapsed: state.sidebarCollapsed,
                    compactMode: state.compactMode,
                    showTooltips: state.showTooltips,
                    autoSave: state.autoSave,
                    confirmDeletion: state.confirmDeletion,
                    // Don't persist session-specific settings
                }),
            }
        ),
        {
            name: 'preferences-store',
        }
    )
);

// Hook for theme effect
export const useThemeEffect = () => {
    const { theme } = usePreferencesStore();

    React.useEffect(() => {
        const root = document.documentElement;

        if (theme === 'dark') {
            root.classList.add('dark');
        } else if (theme === 'light') {
            root.classList.remove('dark');
        } else {
            // System theme
            const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');

            const handleChange = (e: MediaQueryListEvent) => {
                if (e.matches) {
                    root.classList.add('dark');
                } else {
                    root.classList.remove('dark');
                }
            };

            // Set initial theme
            if (mediaQuery.matches) {
                root.classList.add('dark');
            } else {
                root.classList.remove('dark');
            }

            // Listen for changes
            mediaQuery.addEventListener('change', handleChange);

            return () => {
                mediaQuery.removeEventListener('change', handleChange);
            };
        }

        return undefined;
    }, [theme]);
};

// Hook for language effect
export const useLanguageEffect = () => {
    const { language } = usePreferencesStore();

    React.useEffect(() => {
        // Update document language
        document.documentElement.lang = language;

        // Update document direction for RTL languages
        const rtlLanguages = ['ar', 'he', 'fa', 'ur'];
        document.documentElement.dir = rtlLanguages.includes(language) ? 'rtl' : 'ltr';
    }, [language]);
};