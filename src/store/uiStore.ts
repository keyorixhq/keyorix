import { create } from 'zustand';
import { devtools, persist } from 'zustand/middleware';

export type Theme = 'dark' | 'light' | 'system';

interface UIState {
    sidebarOpen: boolean;
    activeModal: string | null;
    modalData: any;
    theme: Theme;
    // which sidebar groups are expanded, keyed by group id
    sidebarExpanded: Record<string, boolean>;

    setSidebarOpen: (open: boolean) => void;
    toggleSidebar: () => void;
    openModal: (modalId: string, data?: any) => void;
    closeModal: () => void;
    setTheme: (theme: Theme) => void;
    toggleTheme: () => void;
    toggleSidebarGroup: (id: string) => void;
}

function resolvedTheme(theme: Theme): 'dark' | 'light' {
    if (theme === 'system') {
        return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    }
    return theme;
}

export function applyTheme(theme: Theme) {
    document.documentElement.setAttribute('data-theme', resolvedTheme(theme));
}

export const useUIStore = create<UIState>()(
    devtools(
        persist(
            (set) => ({
                sidebarOpen: true,
                activeModal: null,
                modalData: null,
                theme: 'dark',
                sidebarExpanded: { secrets: true, access: true, integrations: false, settings: false },

                setSidebarOpen: (open) => set({ sidebarOpen: open }),
                toggleSidebar: () => set((state) => ({ sidebarOpen: !state.sidebarOpen })),
                openModal: (modalId, data = null) => set({ activeModal: modalId, modalData: data }),
                closeModal: () => set({ activeModal: null, modalData: null }),

                setTheme: (theme) => {
                    applyTheme(theme);
                    set({ theme });
                },
                toggleTheme: () =>
                    set((state) => {
                        const next: Theme = state.theme === 'dark' ? 'light' : 'dark';
                        applyTheme(next);
                        return { theme: next };
                    }),
                toggleSidebarGroup: (id) =>
                    set((state) => ({
                        sidebarExpanded: {
                            ...state.sidebarExpanded,
                            [id]: !state.sidebarExpanded[id],
                        },
                    })),
            }),
            {
                name: 'keyorix-ui',
                partialize: (state) => ({ theme: state.theme, sidebarExpanded: state.sidebarExpanded }),
                onRehydrateStorage: () => (state) => {
                    if (state?.theme) applyTheme(state.theme);
                },
            }
        ),
        { name: 'ui-store' }
    )
);
