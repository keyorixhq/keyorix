import React, { useState, useEffect, useRef, useCallback } from 'react';
import { useNavigate } from 'react-router';
import { MagnifyingGlassIcon, FolderIcon, KeyIcon } from '@heroicons/react/24/outline';
import { useProjects } from '../../features/projects/api';
import { apiClient } from '../../services/client';
import { ROUTES } from '../../constants';
import type { Project } from '../../services/projects';

interface SearchResult {
    type: 'project' | 'secret';
    id: number;
    label: string;
    sub: string;
    href: string;
}

function useGlobalSearch(query: string) {
    const [results, setResults] = useState<SearchResult[]>([]);
    const [isSearching, setIsSearching] = useState(false);
    const { data: projects = [] } = useProjects();

    useEffect(() => {
        if (!query.trim()) {
            setResults([]);
            return;
        }
        const q = query.toLowerCase();

        const projectHits: SearchResult[] = projects
            .filter((p: Project) => p.name.toLowerCase().includes(q) || (p.description ?? '').toLowerCase().includes(q))
            .slice(0, 5)
            .map((p: Project) => ({
                type: 'project' as const,
                id: p.id,
                label: p.name,
                sub: p.description ?? '',
                href: ROUTES.PROJECT_DETAIL(p.id),
            }));

        setIsSearching(true);
        apiClient
            .get('/api/v1/secrets', { params: { search: query, pageSize: 8 } })
            .then((res) => {
                const secrets: any[] = res.data.data?.secrets ?? [];
                const secretHits: SearchResult[] = secrets.map((s) => {
                    const projectId = s.ProjectID ?? s.project_id ?? null;
                    const envName = s.environment_name ?? s.environment ?? '';
                    const href = projectId
                        ? `${ROUTES.PROJECT_DETAIL(projectId)}?env=${encodeURIComponent(envName)}`
                        : ROUTES.SECRETS;
                    return {
                        type: 'secret' as const,
                        id: s.ID ?? s.id,
                        label: s.Name ?? s.name,
                        sub: envName ? `${envName}` : '',
                        href,
                    };
                });
                setResults([...projectHits, ...secretHits]);
            })
            .catch(() => setResults(projectHits))
            .finally(() => setIsSearching(false));
    }, [query, projects]);

    return { results, isSearching };
}

interface CmdKSearchProps {
    onClose: () => void;
}

export const CmdKSearch: React.FC<CmdKSearchProps> = ({ onClose }) => {
    const [query, setQuery] = useState('');
    const [debouncedQuery, setDebouncedQuery] = useState('');
    const [activeIndex, setActiveIndex] = useState(0);
    const inputRef = useRef<HTMLInputElement>(null);
    const navigate = useNavigate();

    useEffect(() => {
        const t = setTimeout(() => setDebouncedQuery(query), 250);
        return () => clearTimeout(t);
    }, [query]);

    const { results, isSearching } = useGlobalSearch(debouncedQuery);

    useEffect(() => setActiveIndex(0), [results]);
    useEffect(() => {
        inputRef.current?.focus();
    }, []);

    const handleSelect = useCallback(
        (result: SearchResult) => {
            navigate(result.href);
            onClose();
        },
        [navigate, onClose]
    );

    const handleKeyDown = (e: React.KeyboardEvent) => {
        if (e.key === 'ArrowDown') {
            e.preventDefault();
            setActiveIndex((i) => Math.min(i + 1, results.length - 1));
        } else if (e.key === 'ArrowUp') {
            e.preventDefault();
            setActiveIndex((i) => Math.max(i - 1, 0));
        } else if (e.key === 'Enter' && results[activeIndex]) {
            handleSelect(results[activeIndex]);
        } else if (e.key === 'Escape') {
            onClose();
        }
    };

    return (
        <div className="fixed inset-0 z-50">
            <button
                type="button"
                aria-label="Close search"
                className="absolute inset-0 w-full h-full cursor-default"
                style={{ backgroundColor: 'rgba(0,0,0,0.55)' }}
                onClick={onClose}
            />
            <div className="absolute inset-0 flex items-start justify-center pt-[15vh] pointer-events-none">
                <div
                    className="pointer-events-auto w-full max-w-xl rounded-xl shadow-2xl overflow-hidden"
                    style={{ backgroundColor: 'var(--bg-surface)', border: '1px solid var(--border)' }}
                >
                    {/* Input */}
                    <div
                        className="flex items-center gap-3 px-4 py-3 border-b"
                        style={{ borderColor: 'var(--border)' }}
                    >
                        <MagnifyingGlassIcon className="h-5 w-5 shrink-0" style={{ color: 'var(--text-muted)' }} />
                        <input
                            ref={inputRef}
                            type="text"
                            value={query}
                            onChange={(e) => setQuery(e.target.value)}
                            onKeyDown={handleKeyDown}
                            placeholder="Search projects and secrets…"
                            className="flex-1 bg-transparent outline-hidden text-sm"
                            style={{ color: 'var(--text-primary)' }}
                        />
                        {isSearching && (
                            <div className="animate-spin rounded-full h-3.5 w-3.5 border-b border-blue-500 shrink-0" />
                        )}
                        <kbd
                            className="text-xs px-1.5 py-0.5 rounded-sm"
                            style={{ backgroundColor: 'var(--bg-muted)', color: 'var(--text-muted)' }}
                        >
                            esc
                        </kbd>
                    </div>

                    {/* Results */}
                    {query.trim() && (
                        <ul className="max-h-72 overflow-y-auto py-1">
                            {results.length === 0 && !isSearching && (
                                <li className="px-4 py-8 text-center text-sm" style={{ color: 'var(--text-muted)' }}>
                                    No results for <strong>"{query}"</strong>
                                </li>
                            )}
                            {results.map((result, i) => (
                                <li key={`${result.type}-${result.id}`}>
                                    <button
                                        type="button"
                                        onClick={() => handleSelect(result)}
                                        onMouseEnter={() => setActiveIndex(i)}
                                        className="w-full flex items-center gap-3 px-4 py-2.5 text-left"
                                        style={{
                                            backgroundColor: i === activeIndex ? 'var(--accent-subtle)' : 'transparent',
                                        }}
                                    >
                                        <div
                                            className="shrink-0 h-7 w-7 rounded-sm flex items-center justify-center"
                                            style={{
                                                backgroundColor:
                                                    result.type === 'project'
                                                        ? 'var(--accent-subtle)'
                                                        : 'var(--bg-muted)',
                                            }}
                                        >
                                            {result.type === 'project' ? (
                                                <FolderIcon className="h-4 w-4" style={{ color: 'var(--accent)' }} />
                                            ) : (
                                                <KeyIcon className="h-4 w-4" style={{ color: 'var(--text-muted)' }} />
                                            )}
                                        </div>
                                        <div className="flex-1 min-w-0">
                                            <p
                                                className="text-sm font-medium truncate"
                                                style={{ color: 'var(--text-primary)' }}
                                            >
                                                {result.label}
                                            </p>
                                            {result.sub && (
                                                <p className="text-xs truncate" style={{ color: 'var(--text-muted)' }}>
                                                    {result.sub}
                                                </p>
                                            )}
                                        </div>
                                        <span className="text-xs shrink-0" style={{ color: 'var(--text-muted)' }}>
                                            {result.type}
                                        </span>
                                    </button>
                                </li>
                            ))}
                        </ul>
                    )}

                    {/* Footer hints */}
                    {!query.trim() && (
                        <div
                            className="px-4 py-3 flex items-center gap-4 text-xs"
                            style={{ color: 'var(--text-muted)' }}
                        >
                            <span>
                                <kbd className="px-1 py-0.5 rounded-sm" style={{ backgroundColor: 'var(--bg-muted)' }}>
                                    ↑↓
                                </kbd>{' '}
                                navigate
                            </span>
                            <span>
                                <kbd className="px-1 py-0.5 rounded-sm" style={{ backgroundColor: 'var(--bg-muted)' }}>
                                    ↵
                                </kbd>{' '}
                                open
                            </span>
                            <span>
                                <kbd className="px-1 py-0.5 rounded-sm" style={{ backgroundColor: 'var(--bg-muted)' }}>
                                    esc
                                </kbd>{' '}
                                close
                            </span>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};
