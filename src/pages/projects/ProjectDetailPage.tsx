import React from 'react';
import { Link, useParams, useNavigate, Routes, Route, Navigate } from 'react-router-dom';
import { ChevronRightIcon, FolderIcon } from '@heroicons/react/24/outline';
import { useProject } from '../../features/projects/api';
import { ROUTES } from '../../constants';

// ── Tab definition ───────────────────────────────────────────────────────────

interface Tab {
    id: string;
    label: string;
    path: string;
}

const TABS: Tab[] = [
    { id: 'secrets',  label: 'Secrets',  path: '' },
    { id: 'members',  label: 'Members',  path: '/members' },
    { id: 'activity', label: 'Activity', path: '/activity' },
    { id: 'settings', label: 'Settings', path: '/settings' },
];

// ── Breadcrumb ───────────────────────────────────────────────────────────────

const Breadcrumb: React.FC<{ projectName: string }> = ({ projectName }) => (
    <nav className="flex items-center gap-1.5 text-sm mb-5" style={{ color: 'var(--text-muted)' }}>
        <Link to={ROUTES.PROJECTS} className="hover:underline" style={{ color: 'var(--text-secondary)' }}>
            Projects
        </Link>
        <ChevronRightIcon className="h-3.5 w-3.5 flex-shrink-0" />
        <span style={{ color: 'var(--text-primary)' }}>{projectName}</span>
    </nav>
);

// ── TabNav ───────────────────────────────────────────────────────────────────

const TabNav: React.FC<{ projectId: number; activePath: string }> = ({ projectId, activePath }) => {
    const base = `/projects/${projectId}`;
    // Determine active tab by matching end of current path
    const isActive = (tab: Tab) => {
        if (tab.path === '') {
            return activePath === base || activePath === `${base}/`;
        }
        return activePath.startsWith(`${base}${tab.path}`);
    };

    return (
        <div className="flex gap-1 border-b mb-6" style={{ borderColor: 'var(--border)' }}>
            {TABS.map(tab => {
                const active = isActive(tab);
                return (
                    <Link
                        key={tab.id}
                        to={`${base}${tab.path}`}
                        className="px-4 py-2.5 text-sm font-medium -mb-px border-b-2 transition-colors duration-100"
                        style={{
                            borderBottomColor: active ? 'var(--accent)' : 'transparent',
                            color: active ? 'var(--accent-text)' : 'var(--text-secondary)',
                        }}
                    >
                        {tab.label}
                    </Link>
                );
            })}
        </div>
    );
};

// ── Stub tab content ─────────────────────────────────────────────────────────

const ComingSoonTab: React.FC<{ label: string }> = ({ label }) => (
    <div className="flex flex-col items-center justify-center py-24 text-center">
        <div className="h-10 w-10 rounded-lg flex items-center justify-center mb-3"
            style={{ backgroundColor: 'var(--bg-subtle)' }}>
            <FolderIcon className="h-5 w-5" style={{ color: 'var(--text-muted)' }} />
        </div>
        <p className="text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>{label}</p>
        <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Coming in a future session.</p>
    </div>
);

// ── Secrets tab placeholder (replaced in Phase 3C) ──────────────────────────

const SecretsTab: React.FC<{ projectId: number }> = ({ projectId }) => (
    <div className="flex flex-col items-center justify-center py-24 text-center">
        <div className="h-10 w-10 rounded-lg flex items-center justify-center mb-3"
            style={{ backgroundColor: 'var(--accent-subtle)' }}>
            <FolderIcon className="h-5 w-5" style={{ color: 'var(--accent)' }} />
        </div>
        <p className="text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
            Secrets with environment pills — coming in Phase 3C
        </p>
        <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
            Project ID: {projectId}
        </p>
    </div>
);

// ── ProjectDetailPage ────────────────────────────────────────────────────────

export const ProjectDetailPage: React.FC = () => {
    const { id } = useParams<{ id: string }>();
    const projectId = Number(id);
    const navigate = useNavigate();
    const { data: project, isLoading, isError } = useProject(projectId);

    // Current path for tab highlighting
    const currentPath = window.location.pathname;

    if (isLoading) {
        return (
            <div className="p-6 max-w-5xl mx-auto">
                <div className="animate-pulse">
                    <div className="h-4 w-32 rounded mb-5" style={{ backgroundColor: 'var(--bg-muted)' }} />
                    <div className="h-8 w-56 rounded mb-6" style={{ backgroundColor: 'var(--bg-muted)' }} />
                </div>
            </div>
        );
    }

    if (isError || !project) {
        return (
            <div className="p-6 max-w-5xl mx-auto">
                <Breadcrumb projectName="Unknown" />
                <div className="rounded-lg px-4 py-3 text-sm" style={{ backgroundColor: 'var(--error-subtle)', color: 'var(--error)' }}>
                    Failed to load project.{' '}
                    <button onClick={() => navigate(ROUTES.PROJECTS)} className="underline">
                        Back to Projects
                    </button>
                </div>
            </div>
        );
    }

    return (
        <div className="p-6 max-w-5xl mx-auto">
            <Breadcrumb projectName={project.name} />

            {/* Project header */}
            <div className="flex items-center gap-3 mb-6">
                <div className="h-10 w-10 rounded-lg flex items-center justify-center flex-shrink-0"
                    style={{ backgroundColor: 'var(--accent-subtle)' }}>
                    <FolderIcon className="h-5 w-5" style={{ color: 'var(--accent)' }} />
                </div>
                <div>
                    <h1 className="text-2xl font-semibold" style={{ color: 'var(--text-primary)' }}>
                        {project.name}
                    </h1>
                    {project.description && (
                        <p className="text-sm" style={{ color: 'var(--text-muted)' }}>{project.description}</p>
                    )}
                </div>
            </div>

            {/* Tabs */}
            <TabNav projectId={projectId} activePath={currentPath} />

            {/* Tab content via nested routes */}
            <Routes>
                <Route index element={<SecretsTab projectId={projectId} />} />
                <Route path="members" element={<ComingSoonTab label="Members" />} />
                <Route path="activity" element={<ComingSoonTab label="Activity" />} />
                <Route path="settings" element={<ComingSoonTab label="Settings" />} />
                <Route path="*" element={<Navigate to={`/projects/${projectId}`} replace />} />
            </Routes>
        </div>
    );
};
