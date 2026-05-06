import { create } from 'zustand';
import { devtools, persist } from 'zustand/middleware';

export type Theme = 'dark' | 'light';

interface UIState {
    sidebarOpen: boolean;
    activeModal: string | null;
    modalData: any;
    theme: Theme;

    setSidebarOpen: (open: boolean) => void;
    toggleSidebar: () => void;
    openModal: (modalId: string, data?: any) => void;
    closeModal: () => void;
    setTheme: (theme: Theme) => void;
    toggleTheme: () => void;
}

// Apply theme to <html> data-theme attribute
function applyTheme(theme: Theme) {
    document.documentElement.setAttribute('data-theme', theme);
}

export const useUIStore = create<UIState>()(
    devtools(
        persist(
            (set) => ({
                sidebarOpen: true,
                activeModal: null,
                modalData: null,
                theme: 'dark',

                setSidebarOpen: (open) => set({ sidebarOpen: open }),
                toggleSidebar: () => set((state) => ({ sidebarOpen: !state.sidebarOpen })),
                openModal: (modalId, data = null) => set({ activeModal: modalId, modalData: data }),
                closeModal: () => set({ activeModal: null, modalData: null }),

                setTheme: (theme) => {
                    applyTheme(theme);
                    set({ theme });
                },
                toggleTheme: () => set((state) => {
                    const next: Theme = state.theme === 'dark' ? 'light' : 'dark';
                    applyTheme(next);
                    return { theme: next };
                }),
            }),
            {
                name: 'keyorix-ui',
                // Only persist theme — sidebar state should reset on page load
                partialize: (state) => ({ theme: state.theme }),
                onRehydrateStorage: () => (state) => {
                    // Apply persisted theme immediately after hydration
                    if (state?.theme) {
                        applyTheme(state.theme);
                    }
                },
            }
        ),
        { name: 'ui-store' }
    )
);
