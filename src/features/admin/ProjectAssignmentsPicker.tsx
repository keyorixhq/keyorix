import React, { useMemo, useState } from 'react';
import { XMarkIcon, MagnifyingGlassIcon } from '@heroicons/react/24/outline';
import { useProjects } from '../projects/api';
import { PROJECT_ROLES } from '../../services/projects';
import type { ProjectAssignment } from '../../services/users';

// "project_developer" → "Developer"
const roleLabel = (role: string) => role.replace(/^project_/, '').replace(/^\w/, c => c.toUpperCase());

const DEFAULT_ROLE = 'project_viewer';
// Cap the rendered match list so a 200+ project install stays responsive; the
// search box is the way to reach anything past the cap.
const MAX_RESULTS = 8;

interface ProjectAssignmentsPickerProps {
    assignments: ProjectAssignment[];
    onChange: (next: ProjectAssignment[]) => void;
    disabled?: boolean;
}

/**
 * ADR-028 Global-Admin project-assignment selector. Fetches the project list
 * once and filters it client-side (a typeahead that scales to a few hundred
 * projects), letting an admin attach project-scoped role grants that the atomic
 * POST /users applies in one transaction. Already-assigned projects drop out of
 * the results so a project can't be added twice.
 */
export const ProjectAssignmentsPicker: React.FC<ProjectAssignmentsPickerProps> = ({
    assignments,
    onChange,
    disabled = false,
}) => {
    const { data: projects, isLoading, isError } = useProjects();
    const [query, setQuery] = useState('');

    const assignedIds = useMemo(() => new Set(assignments.map(a => a.project_id)), [assignments]);

    const matches = useMemo(() => {
        const q = query.trim().toLowerCase();
        if (!q) return [];
        return (projects ?? [])
            .filter(p => !p.deleted && !assignedIds.has(p.id) && p.name.toLowerCase().includes(q))
            .slice(0, MAX_RESULTS);
    }, [projects, query, assignedIds]);

    function addProject(id: number, name: string) {
        if (assignedIds.has(id)) return;
        onChange([...assignments, { project_id: id, project_name: name, role: DEFAULT_ROLE }]);
        setQuery('');
    }

    function removeProject(id: number) {
        onChange(assignments.filter(a => a.project_id !== id));
    }

    function setRole(id: number, role: string) {
        onChange(assignments.map(a => (a.project_id === id ? { ...a, role } : a)));
    }

    return (
        <div className="space-y-2">
            <span className="block text-sm font-medium text-base-secondary">Project assignments <span className="font-normal text-base-muted">(optional)</span></span>

            <div className="relative">
                <MagnifyingGlassIcon className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-base-muted" />
                <input
                    type="text"
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                    disabled={disabled || isLoading}
                    placeholder={isLoading ? 'Loading projects…' : 'Search projects to add…'}
                    className="w-full pl-9 pr-3 py-2 text-sm border border-base rounded-lg focus:outline-hidden focus:ring-2 focus:ring-blue-500 disabled:opacity-60"
                />
                {query.trim() && (
                    <div className="absolute z-10 mt-1 w-full max-h-56 overflow-auto rounded-lg border border-base bg-surface shadow-lg">
                        {isError ? (
                            <p className="px-3 py-2 text-sm text-red-600">Couldn’t load projects.</p>
                        ) : matches.length === 0 ? (
                            <p className="px-3 py-2 text-sm text-base-muted">No matching projects.</p>
                        ) : (
                            matches.map(p => (
                                <button
                                    key={p.id}
                                    type="button"
                                    onClick={() => addProject(p.id, p.name)}
                                    className="block w-full px-3 py-2 text-left text-sm text-base-secondary hover:bg-subtle transition-colors"
                                >
                                    {p.name}
                                </button>
                            ))
                        )}
                    </div>
                )}
            </div>

            {assignments.length === 0 ? (
                <p className="text-xs text-base-muted">No projects assigned. The user gets only their system role until added to a project.</p>
            ) : (
                <ul className="space-y-1.5">
                    {assignments.map(a => (
                        <li key={a.project_id} className="flex items-center gap-2 rounded-lg border border-base bg-subtle px-3 py-1.5">
                            <span className="flex-1 min-w-0 truncate text-sm text-base-secondary" title={a.project_name}>
                                {a.project_name || `Project #${a.project_id}`}
                            </span>
                            <select
                                value={a.role}
                                onChange={(e) => setRole(a.project_id, e.target.value)}
                                disabled={disabled}
                                className="shrink-0 px-2 py-1 text-xs border border-base rounded-md bg-surface focus:outline-hidden focus:ring-2 focus:ring-blue-500"
                            >
                                {PROJECT_ROLES.map(r => (
                                    <option key={r} value={r}>{roleLabel(r)}</option>
                                ))}
                            </select>
                            <button
                                type="button"
                                onClick={() => removeProject(a.project_id)}
                                disabled={disabled}
                                title="Remove assignment"
                                className="shrink-0 p-1 text-base-muted hover:text-red-600 hover:bg-red-50 rounded-sm transition-colors"
                            >
                                <XMarkIcon className="h-4 w-4" />
                            </button>
                        </li>
                    ))}
                </ul>
            )}
        </div>
    );
};
