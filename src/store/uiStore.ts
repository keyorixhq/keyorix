import { create } from 'zustand';
import { devtools } from 'zustand/middleware';

interface UIState {
    sidebarOpen: boolean;
    activeModal: string | null;
    modalData: any;

    setSidebarOpen: (open: boolean) => void;
    toggleSidebar: () => void;
    openModal: (modalId: string, data?: any) => void;
    closeModal: () => void;
}

export const useUIStore = create<UIState>()(
    devtools(
        (set) => ({
            sidebarOpen: true,
            activeModal: null,
            modalData: null,

            setSidebarOpen: (open) => set({ sidebarOpen: open }),
            toggleSidebar: () => set((state) => ({ sidebarOpen: !state.sidebarOpen })),
            openModal: (modalId, data = null) => set({ activeModal: modalId, modalData: data }),
            closeModal: () => set({ activeModal: null, modalData: null }),
        }),
        { name: 'ui-store' }
    )
);
