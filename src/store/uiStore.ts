import { create } from 'zustand';
import { devtools } from 'zustand/middleware';

interface UIState {
    // Sidebar state
    sidebarOpen: boolean;

    // Modal states
    activeModal: string | null;
    modalData: any;

    // Page-specific UI state
    currentPage: string;
    pageTitle: string;
    breadcrumbs: BreadcrumbItem[];

    // Table/List UI state
    selectedItems: Set<string | number>;
    bulkActionMode: boolean;

    // Drawer/Panel states
    rightPanelOpen: boolean;
    rightPanelContent: string | null;

    // Focus management
    focusedElement: string | null;
    focusTrap: boolean;

    // Actions
    setSidebarOpen: (open: boolean) => void;
    toggleSidebar: () => void;

    openModal: (modalId: string, data?: any) => void;
    closeModal: () => void;

    setCurrentPage: (page: string, title?: string) => void;
    setBreadcrumbs: (breadcrumbs: BreadcrumbItem[]) => void;

    setSelectedItems: (items: Set<string | number>) => void;
    toggleSelectedItem: (item: string | number) => void;
    clearSelectedItems: () => void;
    setBulkActionMode: (enabled: boolean) => void;

    setRightPanelOpen: (open: boolean, content?: string) => void;
    closeRightPanel: () => void;

    setFocusedElement: (element: string | null) => void;
    setFocusTrap: (enabled: boolean) => void;

    // Utility actions
    reset: () => void;
}

interface BreadcrumbItem {
    label: string;
    href?: string;
    current?: boolean;
}

const initialState = {
    sidebarOpen: true,
    activeModal: null,
    modalData: null,
    currentPage: '',
    pageTitle: '',
    breadcrumbs: [],
    selectedItems: new Set<string | number>(),
    bulkActionMode: false,
    rightPanelOpen: false,
    rightPanelContent: null,
    focusedElement: null,
    focusTrap: false,
};

export const useUIStore = create<UIState>()(
    devtools(
        (set, get) => ({
            ...initialState,

            setSidebarOpen: (open) => {
                set({ sidebarOpen: open });
            },

            toggleSidebar: () => {
                set((state) => ({ sidebarOpen: !state.sidebarOpen }));
            },

            openModal: (modalId, data = null) => {
                set({ activeModal: modalId, modalData: data, focusTrap: true });
            },

            closeModal: () => {
                set({ activeModal: null, modalData: null, focusTrap: false });
            },

            setCurrentPage: (page, title = '') => {
                set({ currentPage: page, pageTitle: title });
            },

            setBreadcrumbs: (breadcrumbs) => {
                set({ breadcrumbs });
            },

            setSelectedItems: (items) => {
                set({ selectedItems: items });
            },

            toggleSelectedItem: (item) => {
                set((state) => {
                    const newSelectedItems = new Set(state.selectedItems);
                    if (newSelectedItems.has(item)) {
                        newSelectedItems.delete(item);
                    } else {
                        newSelectedItems.add(item);
                    }
                    return { selectedItems: newSelectedItems };
                });
            },

            clearSelectedItems: () => {
                set({ selectedItems: new Set(), bulkActionMode: false });
            },

            setBulkActionMode: (enabled) => {
                set({ bulkActionMode: enabled });
                if (!enabled) {
                    set({ selectedItems: new Set() });
                }
            },

            setRightPanelOpen: (open, content) => {
                set({ rightPanelOpen: open, rightPanelContent: content || null });
            },

            closeRightPanel: () => {
                set({ rightPanelOpen: false, rightPanelContent: null });
            },

            setFocusedElement: (element) => {
                set({ focusedElement: element });
            },

            setFocusTrap: (enabled) => {
                set({ focusTrap: enabled });
            },

            reset: () => {
                set({
                    ...initialState,
                    selectedItems: new Set<string | number>(),
                });
            },
        }),
        {
            name: 'ui-store',
        }
    )
);

// Hook for managing selected items
export const useSelectedItems = () => {
    const {
        selectedItems,
        bulkActionMode,
        setSelectedItems,
        toggleSelectedItem,
        clearSelectedItems,
        setBulkActionMode,
    } = useUIStore();

    const selectAll = (items: (string | number)[]) => {
        setSelectedItems(new Set(items));
    };

    const isSelected = (item: string | number) => {
        return selectedItems.has(item);
    };

    const getSelectedCount = () => {
        return selectedItems.size;
    };

    const hasSelection = () => {
        return selectedItems.size > 0;
    };

    return {
        selectedItems,
        bulkActionMode,
        toggleSelectedItem,
        clearSelectedItems,
        setBulkActionMode,
        selectAll,
        isSelected,
        getSelectedCount,
        hasSelection,
    };
};