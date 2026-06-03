import React, { useState, useRef, useEffect, useCallback } from 'react';
import { useNavigate, useLocation, Link } from 'react-router-dom';
import {
    FolderIcon,
    ChevronUpDownIcon,
    MagnifyingGlassIcon,
    PlusIcon,
    CheckIcon,
} from '@heroicons/react/24/outline';
import { useProjects } from '../../features/projects/api';

// ── helpers ───────────────────────────────────────────────────────────────────

function useCurrentProjectId(): number | null {
    const { pathname } = useLocation();
    const match = pathname.match(/^\/projects\/(\d+)/);
    return match?.[1] ? parseInt(match[1], 10) : null;
}

// ── component ─────────────────────────────────────────────────────────────────

interface ProjectSwitcherProps {
    onNavigate?: () => void; // called after navigation (closes mobile sidebar)
}

export const ProjectSwitcher: React.FC<ProjectSwitcherProps> = ({ onNavigate }) => {
    const navigate = useNavigate();
    const { data: projects = [], isLoading } = useProjects();
    const currentProjectId = useCurrentProjectId();

    const [open, setOpen] = useState(false);
    const [search, setSearch] = useState('');
    const containerRef = useRef<HTMLDivElement>(null);
    const searchRef = useRef<HTMLInputElement>(null);

    const currentProject = projects.find(p => p.id === currentProjectId) ?? null;

    // Close on outside click
    useEffect(() => {
        if (!open) return;
        const handler = (e: MouseEvent) => {
            if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
                setOpen(false);
                setSearch('');
            }
        };
        document.addEventListener('mousedown', handler);
        return () => document.removeEventListener('mousedown', handler);
    }, [open]);

    // Focus search when dropdown opens
    useEffect(() => {
        if (open) setTimeout(() => searchRef.current?.focus(), 50);
    }, [open]);

    const filtered = search.trim()
        ? projects.filter(p => p.name.toLowerCase().includes(search.toLowerCase()))
        : projects.slice(0, 5);

    const handleSelect = useCallback((id: number) => {
        setOpen(false);
        setSearch('');
        navigate(`/projects/${id}`);
        onNavigate?.();
    }, [navigate, onNavigate]);

    const handleNewProject = useCallback(() => {
        setOpen(false);
        setSearch('');
        navigate('/projects?new=1');
        onNavigate?.();
    }, [navigate, onNavigate]);

    return (
        <div ref={containerRef} className="relative px-3 pb-3">
            {/* Trigger button */}
            <button
                type="button"
                onClick={() => setOpen(o => !o)}
                className="w-full flex items-center gap-2.5 px-2.5 py-2 rounded-lg text-sm transition-colors duration-100"
                style={{
                    backgroundColor: open ? 'var(--bg-subtle)' : 'transparent',
                    border: '1px solid var(--border)',
                    color: 'var(--text-secondary)',
                }}
                onMouseEnter={e => {
                    if (!open) (e.currentTarget as HTMLElement).style.backgroundColor = 'var(--bg-subtle)';
                }}
                onMouseLeave={e => {
                    if (!open) (e.currentTarget as HTMLElement).style.backgroundColor = 'transparent';
                }}
            >
                <div
                    className="h-5 w-5 rounded-sm flex items-center justify-center shrink-0"
                    style={{ backgroundColor: 'var(--accent-subtle)' }}
                >
                    <FolderIcon className="h-3 w-3" style={{ color: 'var(--accent)' }} />
                </div>
                <span className="flex-1 text-left truncate text-xs font-medium" style={{ color: 'var(--text-primary)' }}>
                    {isLoading ? 'Loading…' : currentProject ? currentProject.name : 'Select project'}
                </span>
                <ChevronUpDownIcon className="h-3.5 w-3.5 shrink-0" style={{ color: 'var(--text-muted)' }} />
            </button>

            {/* Dropdown */}
            {open && (
                <div
                    className="absolute left-3 right-3 top-full mt-1 rounded-lg shadow-lg z-50 overflow-hidden"
                    style={{
                        backgroundColor: 'var(--bg-surface)',
                        border: '1px solid var(--border)',
                        boxShadow: '0 8px 24px rgba(0,0,0,0.18)',
                    }}
                >
                    {/* Search */}
                    <div className="p-2 border-b" style={{ borderColor: 'var(--border)' }}>
                        <div className="relative">
                            <MagnifyingGlassIcon
                                className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5"
                                style={{ color: 'var(--text-muted)' }}
                            />
                            <input
                                ref={searchRef}
                                type="text"
                                value={search}
                                onChange={e => setSearch(e.target.value)}
                                placeholder="Search projects…"
                                className="w-full pl-8 pr-3 py-1.5 text-xs rounded-md outline-hidden"
                                style={{
                                    backgroundColor: 'var(--bg-app)',
                                    border: '1px solid var(--border)',
                                    color: 'var(--text-primary)',
                                }}
                            />
                        </div>
                    </div>

                    {/* Project list */}
                    <div className="max-h-48 overflow-y-auto py-1">
                        {filtered.length === 0 ? (
                            <p className="px-3 py-4 text-xs text-center" style={{ color: 'var(--text-muted)' }}>
                                {search ? `No projects matching "${search}"` : 'No projects yet'}
                            </p>
                        ) : (
                            filtered.map(project => {
                                const isCurrent = project.id === currentProjectId;
                                return (
                                    <button
                                        key={project.id}
                                        type="button"
                                        onClick={() => handleSelect(project.id)}
                                        className="w-full flex items-center gap-2.5 px-3 py-2 text-left transition-colors duration-75"
                                        style={{ color: 'var(--text-secondary)' }}
                                        onMouseEnter={e => (e.currentTarget as HTMLElement).style.backgroundColor = 'var(--bg-subtle)'}
                                        onMouseLeave={e => (e.currentTarget as HTMLElement).style.backgroundColor = ''}
                                    >
                                        <div
                                            className="h-5 w-5 rounded-sm flex items-center justify-center shrink-0"
                                            style={{ backgroundColor: isCurrent ? 'var(--accent-subtle)' : 'var(--bg-muted)' }}
                                        >
                                            <FolderIcon
                                                className="h-3 w-3"
                                                style={{ color: isCurrent ? 'var(--accent)' : 'var(--text-muted)' }}
                                            />
                                        </div>
                                        <div className="flex-1 min-w-0">
                                            <p className="text-xs font-medium truncate" style={{ color: 'var(--text-primary)' }}>
                                                {project.name}
                                            </p>
                                            {project.secretCount != null && (
                                                <p className="text-[10px]" style={{ color: 'var(--text-muted)' }}>
                                                    {project.secretCount} secret{project.secretCount !== 1 ? 's' : ''}
                                                    {project.environmentCount != null && ` · ${project.environmentCount} envs`}
                                                </p>
                                            )}
                                        </div>
                                        {isCurrent && (
                                            <CheckIcon className="h-3.5 w-3.5 shrink-0" style={{ color: 'var(--accent)' }} />
                                        )}
                                    </button>
                                );
                            })
                        )}
                    </div>

                    {/* Footer actions */}
                    <div className="border-t py-1" style={{ borderColor: 'var(--border)' }}>
                        <Link
                            to="/projects"
                            onClick={() => { setOpen(false); setSearch(''); onNavigate?.(); }}
                            className="flex items-center gap-2 px-3 py-2 text-xs transition-colors duration-75"
                            style={{ color: 'var(--text-muted)' }}
                            onMouseEnter={e => (e.currentTarget as HTMLElement).style.backgroundColor = 'var(--bg-subtle)'}
                            onMouseLeave={e => (e.currentTarget as HTMLElement).style.backgroundColor = ''}
                        >
                            <FolderIcon className="h-3.5 w-3.5 shrink-0" />
                            All projects
                        </Link>
                        <button
                            type="button"
                            onClick={handleNewProject}
                            className="w-full flex items-center gap-2 px-3 py-2 text-xs transition-colors duration-75"
                            style={{ color: 'var(--text-muted)' }}
                            onMouseEnter={e => (e.currentTarget as HTMLElement).style.backgroundColor = 'var(--bg-subtle)'}
                            onMouseLeave={e => (e.currentTarget as HTMLElement).style.backgroundColor = ''}
                        >
                            <PlusIcon className="h-3.5 w-3.5 shrink-0" />
                            New project
                        </button>
                    </div>
                </div>
            )}
        </div>
    );
};
