import { create } from 'zustand';
import { devtools, persist } from 'zustand/middleware';

// Most-recently-used project ordering for the sidebar project switcher (ADR-018).
// Client-side MRU list of project IDs, most-recent-first. Server-side
// last_accessed_at is a later enhancement; localStorage is the interim source.

const MAX_RECENT = 10;

interface ProjectMruState {
    // project IDs, most-recent-first
    recentIds: number[];
    // record that a project was just accessed; moves it to the front
    recordAccess: (id: number) => void;
}

export const useProjectMruStore = create<ProjectMruState>()(
    devtools(
        persist(
            (set) => ({
                recentIds: [],
                recordAccess: (id) =>
                    set((state) => {
                        if (!Number.isFinite(id)) return state;
                        const next = [id, ...state.recentIds.filter((x) => x !== id)].slice(0, MAX_RECENT);
                        return { recentIds: next };
                    }),
            }),
            {
                name: 'keyorix-project-mru',
                partialize: (state) => ({ recentIds: state.recentIds }),
            }
        ),
        { name: 'project-mru-store' }
    )
);
