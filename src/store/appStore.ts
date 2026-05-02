import React from 'react';
import { create } from 'zustand';
import { devtools } from 'zustand/middleware';
import { EnvironmentConfig, DashboardStats } from '../types';

interface AppState {
    // Application metadata
    version: string;
    buildTime: string;
    environment: 'development' | 'staging' | 'production';

    // System status
    isOnline: boolean;
    serverStatus: 'online' | 'offline' | 'maintenance' | 'unknown';
    lastServerCheck: string | null;

    // Global loading states
    initializing: boolean;
    globalLoading: boolean;
    loadingMessage: string;

    // Feature flags
    features: Record<string, boolean>;

    // System configuration
    config: Partial<EnvironmentConfig>;

    // Dashboard data (cached)
    dashboardStats: DashboardStats | null;
    lastStatsUpdate: string | null;

    // Global search
    globalSearchOpen: boolean;
    globalSearchQuery: string;
    globalSearchResults: any[];
    globalSearchLoading: boolean;

    // Command palette
    commandPaletteOpen: boolean;

    // Keyboard shortcuts
    shortcutsEnabled: boolean;

    // Actions
    setVersion: (version: string) => void;
    setBuildTime: (buildTime: string) => void;
    setEnvironment: (environment: 'development' | 'staging' | 'production') => void;

    setOnlineStatus: (isOnline: boolean) => void;
    setServerStatus: (status: 'online' | 'offline' | 'maintenance' | 'unknown') => void;
    updateServerCheck: () => void;

    setInitializing: (initializing: boolean) => void;
    setGlobalLoading: (loading: boolean, message?: string) => void;

    setFeature: (feature: string, enabled: boolean) => void;
    toggleFeature: (feature: string) => void;
    isFeatureEnabled: (feature: string) => boolean;

    updateConfig: (config: Partial<EnvironmentConfig>) => void;

    setDashboardStats: (stats: DashboardStats) => void;
    clearDashboardStats: () => void;

    setGlobalSearchOpen: (open: boolean) => void;
    setGlobalSearchQuery: (query: string) => void;
    setGlobalSearchResults: (results: any[]) => void;
    setGlobalSearchLoading: (loading: boolean) => void;

    setCommandPaletteOpen: (open: boolean) => void;

    setShortcutsEnabled: (enabled: boolean) => void;

    // Utility actions
    reset: () => void;
    initialize: (config: Partial<EnvironmentConfig>) => void;
}

const initialState = {
    version: '1.0.0',
    buildTime: '',
    environment: 'development' as const,
    isOnline: navigator.onLine,
    serverStatus: 'unknown' as const,
    lastServerCheck: null,
    initializing: true,
    globalLoading: false,
    loadingMessage: '',
    features: {},
    config: {},
    dashboardStats: null,
    lastStatsUpdate: null,
    globalSearchOpen: false,
    globalSearchQuery: '',
    globalSearchResults: [],
    globalSearchLoading: false,
    commandPaletteOpen: false,
    shortcutsEnabled: true,
};

export const useAppStore = create<AppState>()(
    devtools(
        (set, get) => ({
            ...initialState,

            setVersion: (version) => {
                set({ version });
            },

            setBuildTime: (buildTime) => {
                set({ buildTime });
            },

            setEnvironment: (environment) => {
                set({ environment });
            },

            setOnlineStatus: (isOnline) => {
                set({ isOnline });
            },

            setServerStatus: (status) => {
                set({ serverStatus: status });
            },

            updateServerCheck: () => {
                set({ lastServerCheck: new Date().toISOString() });
            },

            setInitializing: (initializing) => {
                set({ initializing });
            },

            setGlobalLoading: (loading, message = '') => {
                set({ globalLoading: loading, loadingMessage: message });
            },

            setFeature: (feature, enabled) => {
                set((state) => ({
                    features: {
                        ...state.features,
                        [feature]: enabled,
                    },
                }));
            },

            toggleFeature: (feature) => {
                set((state) => ({
                    features: {
                        ...state.features,
                        [feature]: !state.features[feature],
                    },
                }));
            },

            isFeatureEnabled: (feature) => {
                return get().features[feature] ?? false;
            },

            updateConfig: (config) => {
                set((state) => ({
                    config: {
                        ...state.config,
                        ...config,
                    },
                }));
            },

            setDashboardStats: (stats) => {
                set({
                    dashboardStats: stats,
                    lastStatsUpdate: new Date().toISOString(),
                });
            },

            clearDashboardStats: () => {
                set({
                    dashboardStats: null,
                    lastStatsUpdate: null,
                });
            },

            setGlobalSearchOpen: (open) => {
                set({ globalSearchOpen: open });
                if (!open) {
                    set({
                        globalSearchQuery: '',
                        globalSearchResults: [],
                        globalSearchLoading: false,
                    });
                }
            },

            setGlobalSearchQuery: (query) => {
                set({ globalSearchQuery: query });
            },

            setGlobalSearchResults: (results) => {
                set({ globalSearchResults: results });
            },

            setGlobalSearchLoading: (loading) => {
                set({ globalSearchLoading: loading });
            },

            setCommandPaletteOpen: (open) => {
                set({ commandPaletteOpen: open });
            },

            setShortcutsEnabled: (enabled) => {
                set({ shortcutsEnabled: enabled });
            },

            reset: () => {
                set(initialState);
            },

            initialize: (config) => {
                set((state) => ({
                    ...state,
                    config: {
                        ...state.config,
                        ...config,
                    },
                    version: config.APP_VERSION || state.version,
                    environment: config.ENVIRONMENT || state.environment,
                    initializing: false,
                }));
            },
        }),
        {
            name: 'app-store',
        }
    )
);

// Hook for online status effect
export const useOnlineStatusEffect = () => {
    const setOnlineStatus = useAppStore((state) => state.setOnlineStatus);

    React.useEffect(() => {
        const handleOnline = () => setOnlineStatus(true);
        const handleOffline = () => setOnlineStatus(false);

        window.addEventListener('online', handleOnline);
        window.addEventListener('offline', handleOffline);

        return () => {
            window.removeEventListener('online', handleOnline);
            window.removeEventListener('offline', handleOffline);
        };
    }, [setOnlineStatus]);
};

// Hook for keyboard shortcuts
export const useKeyboardShortcuts = () => {
    const {
        shortcutsEnabled,
        setGlobalSearchOpen,
        setCommandPaletteOpen,
        globalSearchOpen,
        commandPaletteOpen,
    } = useAppStore();

    React.useEffect(() => {
        if (!shortcutsEnabled) return;

        const handleKeyDown = (event: KeyboardEvent) => {
            // Cmd/Ctrl + K for global search
            if ((event.metaKey || event.ctrlKey) && event.key === 'k') {
                event.preventDefault();
                setGlobalSearchOpen(!globalSearchOpen);
            }

            // Cmd/Ctrl + Shift + P for command palette
            if ((event.metaKey || event.ctrlKey) && event.shiftKey && event.key === 'P') {
                event.preventDefault();
                setCommandPaletteOpen(!commandPaletteOpen);
            }

            // Escape to close modals
            if (event.key === 'Escape') {
                if (globalSearchOpen) {
                    setGlobalSearchOpen(false);
                }
                if (commandPaletteOpen) {
                    setCommandPaletteOpen(false);
                }
            }
        };

        document.addEventListener('keydown', handleKeyDown);

        return () => {
            document.removeEventListener('keydown', handleKeyDown);
        };
    }, [
        shortcutsEnabled,
        globalSearchOpen,
        commandPaletteOpen,
        setGlobalSearchOpen,
        setCommandPaletteOpen,
    ]);
};