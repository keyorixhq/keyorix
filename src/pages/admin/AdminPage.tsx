import React, { useState } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { ROUTES } from '../../constants';
import {
    MagnifyingGlassIcon,
    PlusIcon,
    ChevronLeftIcon,
    ChevronRightIcon,
    TrashIcon,
    PencilIcon,
    UserCircleIcon,
    ShieldCheckIcon,
    ArrowPathIcon,
} from '@heroicons/react/24/outline';
import {
    useAdminUserList,
    useAdminCreateUser,
    useAdminUpdateUser,
    useAdminDeleteUser,
    useAdminRestoreUser,
    useAdminRoles,
    useUserRoles,
    useUpdateUserRoles,
} from '../../features/admin';
import { Button } from '../../components/ui/Button';
import { Modal } from '../../components/ui/Modal';
import { Alert } from '../../components/ui/Alert';
import { Loading } from '../../components/ui/Loading';
import { useUIStore } from '../../store/uiStore';

interface APIUser {
    id: number;
    username: string;
    email: string;
    display_name: string;
    active: boolean;
    created_at: string;
    updated_at: string;
    deleted_at: string | null;
}

type ActiveModal =
    | null
    | { type: 'create' }
    | { type: 'edit'; user: APIUser }
    | { type: 'delete'; user: APIUser }
    | { type: 'restore'; user: APIUser }
    | { type: 'roles'; user: APIUser };

function formatDate(iso: string): string {
    if (!iso) return '—';
    try {
        return new Date(iso).toLocaleDateString(undefined, {
            year: 'numeric', month: 'short', day: 'numeric',
        });
    } catch {
        return iso;
    }
}

function generatePassword(): string {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$%^&*';
    const arr = new Uint8Array(16);
    window.crypto.getRandomValues(arr);
    return Array.from(arr).map(b => chars[b % chars.length]).join('');
}

export const AdminPage: React.FC = () => {
    const PAGE_SIZE = 20;

    const [searchParams] = useSearchParams();
    const [page, setPage] = useState(1);
    const [search, setSearch] = useState('');
    const [searchInput, setSearchInput] = useState('');
    const [showDeleted, setShowDeleted] = useState(false);
    const filterInactive = searchParams.get('filter') === 'inactive';
    const [activeModal, setActiveModal] = useState<ActiveModal>(null);
    const [formError, setFormError] = useState('');
    const [pageError, setPageError] = useState('');
    const [selected, setSelected] = useState<Set<number>>(new Set());
    const [bulkPending, setBulkPending] = useState(false);

    const [createUsername, setCreateUsername] = useState('');
    const [createEmail, setCreateEmail] = useState('');
    const [createDisplayName, setCreateDisplayName] = useState('');
    const [createPassword, setCreatePassword] = useState('');
    const [showPassword, setShowPassword] = useState(false);

    const [editEmail, setEditEmail] = useState('');
    const [editDisplayName, setEditDisplayName] = useState('');
    const [editActive, setEditActive] = useState(true);

    const navigate = useNavigate();
    const { theme } = useUIStore();
    const isDark = theme === 'dark' || (theme === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches);
    const { data, isLoading, isError } = useAdminUserList({ page, search, pageSize: PAGE_SIZE, includeDeleted: showDeleted });

    const rawData = data as any;
    const users: APIUser[] = rawData?.users ?? [];
    const total: number = rawData?.total ?? 0;
    const totalPages: number = rawData?.total_pages ?? 1;

    const [rolesUserId, setRolesUserId] = useState<number | null>(null);
    const [selectedRoleIds, setSelectedRoleIds] = useState<Set<number>>(new Set());

    const createMutation = useAdminCreateUser();
    const updateMutation = useAdminUpdateUser();
    const deleteMutation = useAdminDeleteUser();
    const restoreMutation = useAdminRestoreUser();
    const { data: allRoles } = useAdminRoles();
    const { data: userRolesData, isLoading: rolesLoading } = useUserRoles(rolesUserId);
    const updateRolesMutation = useUpdateUserRoles();

    function closeModal() {
        setActiveModal(null);
        setFormError('');
        setCreateUsername(''); setCreateEmail(''); setCreateDisplayName(''); setCreatePassword('');
        setShowPassword(false);
        setRolesUserId(null);
        setSelectedRoleIds(new Set());
    }

    function openRoles(user: APIUser) {
        setRolesUserId(user.id);
        setFormError('');
        setActiveModal({ type: 'roles', user });
    }

    function handleRolesOpen(user: APIUser) {
        openRoles(user);
    }

    React.useEffect(() => {
        if (userRolesData && activeModal?.type === 'roles') {
            setSelectedRoleIds(new Set(userRolesData.map((r: { id: number }) => r.id)));
        }
    }, [userRolesData, activeModal?.type]);

    function toggleRoleId(id: number) {
        setSelectedRoleIds(prev => {
            const next = new Set(prev);
            next.has(id) ? next.delete(id) : next.add(id);
            return next;
        });
    }

    function handleSaveRoles() {
        if (activeModal?.type !== 'roles') return;
        if (selectedRoleIds.size === 0) { setFormError('User must have at least one role'); return; }
        setFormError('');
        updateRolesMutation.mutate(
            { userId: activeModal.user.id, roleIds: Array.from(selectedRoleIds) },
            {
                onSuccess: () => { closeModal(); },
                onError: (err: any) => setFormError(err.response?.data?.error ?? err.message ?? 'Failed to update roles'),
            }
        );
    }

    function openEdit(user: APIUser) {
        setEditEmail(user.email);
        setEditDisplayName(user.display_name);
        setEditActive(user.active);
        setFormError('');
        setActiveModal({ type: 'edit', user });
    }

    function handleCreate() {
        setFormError('');
        if (!createUsername.trim()) { setFormError('Username is required'); return; }
        if (!createEmail.trim()) { setFormError('Email is required'); return; }
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(createEmail.trim())) { setFormError('Please enter a valid email address'); return; }
        if (!createDisplayName.trim()) { setFormError('Display name is required'); return; }
        if (createPassword.length < 8) { setFormError('Password must be at least 8 characters'); return; }
        createMutation.mutate(
            { username: createUsername.trim(), email: createEmail.trim(), display_name: createDisplayName.trim(), password: createPassword },
            {
                onSuccess: closeModal,
                onError: (err: any) => setFormError(err.response?.data?.error ?? err.message ?? 'Failed to create user'),
            }
        );
    }

    function handleUpdate() {
        if (activeModal?.type !== 'edit') return;
        setFormError('');
        if (!editEmail.trim()) { setFormError('Email is required'); return; }
        updateMutation.mutate(
            { id: activeModal.user.id, body: { email: editEmail.trim(), display_name: editDisplayName.trim(), active: editActive } },
            {
                onSuccess: closeModal,
                onError: (err: any) => setFormError(err.response?.data?.error ?? err.message ?? 'Failed to update user'),
            }
        );
    }

    function handleDelete() {
        if (activeModal?.type !== 'delete') return;
        deleteMutation.mutate(activeModal.user.id, {
            onSuccess: closeModal,
            onError: (err: any) => setPageError(err.response?.data?.error ?? err.message ?? 'Failed to delete user'),
        });
    }

    function handleRestore() {
        if (activeModal?.type !== 'restore') return;
        restoreMutation.mutate(activeModal.user.id, {
            onSuccess: closeModal,
            onError: (err: any) => setPageError(err.response?.data?.error ?? err.message ?? 'Failed to restore user'),
        });
    }

    function toggleSelect(id: number) {
        setSelected(prev => { const s = new Set(prev); s.has(id) ? s.delete(id) : s.add(id); return s; });
    }

    function toggleAll() {
        setSelected(prev => prev.size === users.length ? new Set() : new Set(users.map(u => u.id)));
    }

    async function bulkSetActive(active: boolean) {
        const targets = users.filter(u => selected.has(u.id) && u.active !== active);
        if (!targets.length) return;
        setBulkPending(true);
        try {
            await Promise.all(targets.map(u =>
                updateMutation.mutateAsync({ id: u.id, body: { email: u.email, display_name: u.display_name, active } })
            ));
            setSelected(new Set());
        } catch (err: any) {
            setPageError(err.response?.data?.error ?? err.message ?? 'Bulk action failed');
        } finally {
            setBulkPending(false);
        }
    }

    async function bulkDelete() {
        setBulkPending(true);
        try {
            await Promise.all(Array.from(selected).map(id => deleteMutation.mutateAsync(id)));
            setSelected(new Set());
        } catch (err: any) {
            setPageError(err.response?.data?.error ?? err.message ?? 'Bulk delete failed');
        } finally {
            setBulkPending(false);
        }
    }

    const hasActive = users.some(u => selected.has(u.id) && u.active);
    const hasInactive = users.some(u => selected.has(u.id) && !u.active);

    return (
        <>
            <div className="max-w-6xl mx-auto px-4 py-8">
                <div className="flex items-center justify-between mb-6">
                    <div>
                        <h1 className="text-2xl font-bold text-base-primary">User Management</h1>
                        <p className="text-sm text-base-muted mt-1">
                            {total > 0 ? `${total} user${total !== 1 ? 's' : ''}` : 'No users found'}
                        </p>
                    </div>
                    <div className="flex items-center gap-2">
                        {selected.size > 0 && (
                            <>
                                <span className="text-sm text-base-muted">{selected.size} selected</span>
                                {hasInactive && (
                                    <Button variant="outline" size="sm" onClick={() => bulkSetActive(true)} disabled={bulkPending}>
                                        Activate
                                    </Button>
                                )}
                                {hasActive && (
                                    <Button variant="outline" size="sm" onClick={() => bulkSetActive(false)} disabled={bulkPending}>
                                        Deactivate
                                    </Button>
                                )}
                                <Button variant="outline" size="sm" onClick={bulkDelete} disabled={bulkPending} className="text-red-600 hover:text-red-700">
                                    <TrashIcon className="h-4 w-4 mr-1" />Delete
                                </Button>
                                <Button variant="ghost" size="sm" onClick={() => setSelected(new Set())}>Clear</Button>
                            </>
                        )}
                        <Button variant="primary" onClick={() => { setFormError(''); setActiveModal({ type: 'create' }); }}>
                            <PlusIcon className="h-4 w-4 mr-1.5" />New User
                        </Button>
                    </div>
                </div>

                {pageError && (
                    <Alert type="error" title={pageError} dismissible onDismiss={() => setPageError('')} className="mb-4" />
                )}

                {filterInactive && (
                    <div className="flex items-center justify-between px-4 py-2.5 mb-4 rounded-lg border"
                        style={{ backgroundColor: isDark ? 'rgba(217,119,6,0.12)' : '#fffbeb', borderColor: isDark ? 'rgba(217,119,6,0.35)' : '#fcd34d', color: isDark ? '#fbbf24' : '#92400e' }}>
                        <span className="text-sm font-medium">Inactive users = no login in 30 days. All users shown — check Audit Log for login history.</span>
                        <button
                            type="button"
                            onClick={() => navigate(ROUTES.AUDIT + '?tab=audit&filter=logins')}
                            className="text-sm font-medium underline underline-offset-2 hover:opacity-75 transition-opacity ml-4 whitespace-nowrap"
                        >
                            View login history →
                        </button>
                    </div>
                )}

                <div className="flex flex-col gap-3 mb-6">
                    <form onSubmit={(e) => { e.preventDefault(); setSearch(searchInput); setPage(1); }} className="flex gap-2">
                        <div className="relative flex-1">
                            <MagnifyingGlassIcon className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-base-muted" />
                            <input
                                type="text"
                                placeholder="Search by username or email…"
                                value={searchInput}
                                onChange={(e) => setSearchInput(e.target.value)}
                                className="w-full pl-9 pr-4 py-2 text-sm border border-base rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent" style={{ backgroundColor: 'var(--bg-app)', color: 'var(--text-primary)', borderColor: 'var(--border-strong)' }}
                            />
                        </div>
                        <Button type="submit" variant="secondary">Search</Button>
                        {search && (
                            <Button type="button" variant="ghost" onClick={() => { setSearchInput(''); setSearch(''); setPage(1); }}>Clear</Button>
                        )}
                    </form>
                    <label className="flex items-center gap-2 cursor-pointer w-fit">
                        <input
                            type="checkbox"
                            checked={showDeleted}
                            onChange={(e) => { setShowDeleted(e.target.checked); setPage(1); setSelected(new Set()); }}
                            className="h-4 w-4 rounded border-base"
                            style={{ accentColor: 'var(--accent)' }}
                        />
                        <span className="text-sm text-base-muted">Show deleted users</span>
                    </label>
                </div>

                {isLoading ? (
                    <Loading className="py-20" />
                ) : isError ? (
                    <Alert type="error" title="Failed to load users" message="Check that the server is running and you have admin access." />
                ) : users.length === 0 ? (
                    <div className="text-center py-20 text-base-muted">
                        <UserCircleIcon className="h-12 w-12 mx-auto mb-3 text-base-muted" />
                        <p className="text-sm">{search ? 'No users match your search.' : 'No users yet.'}</p>
                    </div>
                ) : (
                    <div className="bg-surface border border-base rounded-lg overflow-hidden shadow-sm">
                        <table className="min-w-full divide-y divide-base">
                            <thead>
                                <tr>
                                    <th className="px-4 py-3 w-10">
                                        <input type="checkbox" className="rounded border-base text-blue-600 focus:ring-blue-500" style={{ accentColor: 'var(--accent)' }}
                                            checked={users.length > 0 && selected.size === users.length}
                                            onChange={toggleAll} />
                                    </th>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-base-muted uppercase tracking-wider">User</th>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-base-muted uppercase tracking-wider">Email</th>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-base-muted uppercase tracking-wider">Status</th>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-base-muted uppercase tracking-wider">Created</th>
                                    <th className="px-6 py-3 text-right text-xs font-medium text-base-muted uppercase tracking-wider">Actions</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-base">
                                {users.map((user) => (
                                    <tr key={user.id} className={`hover:bg-subtle transition-colors ${selected.has(user.id) ? 'bg-accent-subtle' : ''}`}>
                                        <td className="px-4 py-4 w-10">
                                            <input type="checkbox" className="rounded border-base text-blue-600 focus:ring-blue-500" style={{ accentColor: 'var(--accent)' }}
                                                checked={selected.has(user.id)}
                                                onChange={() => toggleSelect(user.id)} />
                                        </td>
                                        <td className="px-6 py-4 whitespace-nowrap">
                                            <div className="flex items-center gap-3">
                                                <div className="flex-shrink-0 h-8 w-8 rounded-full bg-blue-100 flex items-center justify-center">
                                                    <span className="text-xs font-semibold text-blue-700">
                                                        {(user.display_name || user.username).charAt(0).toUpperCase()}
                                                    </span>
                                                </div>
                                                <div>
                                                    <p className="text-sm font-medium text-base-primary">{user.display_name || user.username}</p>
                                                    <p className="text-xs text-base-muted">@{user.username}</p>
                                                </div>
                                            </div>
                                        </td>
                                        <td className="px-6 py-4 whitespace-nowrap text-sm text-base-secondary">{user.email}</td>
                                        <td className="px-6 py-4 whitespace-nowrap">
                                            {user.deleted_at ? (
                                                <span
                                                    className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium"
                                                    style={{ backgroundColor: isDark ? 'rgba(239,68,68,0.15)' : '#fee2e2', color: isDark ? '#f87171' : '#991b1b' }}
                                                >
                                                    Deleted
                                                </span>
                                            ) : (
                                                <span
                                                    className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium"
                                                    style={user.active
                                                        ? { backgroundColor: isDark ? 'rgba(16,185,129,0.15)' : '#dcfce7', color: isDark ? '#34d399' : '#166534' }
                                                        : { backgroundColor: isDark ? 'rgba(148,163,184,0.15)' : '#f1f5f9', color: isDark ? '#94a3b8' : '#475569' }}
                                                >
                                                    {user.active ? 'Active' : 'Inactive'}
                                                </span>
                                            )}
                                        </td>
                                        <td className="px-6 py-4 whitespace-nowrap text-sm text-base-muted">{formatDate(user.created_at)}</td>
                                        <td className="px-6 py-4 whitespace-nowrap text-right">
                                            <div className="flex items-center justify-end gap-2">
                                                {user.deleted_at ? (
                                                    <button onClick={() => setActiveModal({ type: 'restore', user })} className="p-1.5 text-base-muted hover:text-green-600 hover:bg-green-50 rounded transition-colors" title="Restore user">
                                                        <ArrowPathIcon className="h-4 w-4" />
                                                    </button>
                                                ) : (
                                                    <>
                                                        <button onClick={() => handleRolesOpen(user)} className="p-1.5 text-base-muted hover:text-blue-600 hover:bg-accent-subtle rounded transition-colors" title="Manage roles">
                                                            <ShieldCheckIcon className="h-4 w-4" />
                                                        </button>
                                                        <button onClick={() => openEdit(user)} className="p-1.5 text-base-muted hover:text-blue-600 hover:bg-accent-subtle rounded transition-colors" title="Edit user">
                                                            <PencilIcon className="h-4 w-4" />
                                                        </button>
                                                        <button onClick={() => setActiveModal({ type: 'delete', user })} className="p-1.5 text-base-muted hover:text-red-600 hover:bg-red-50 rounded transition-colors" title="Delete user">
                                                            <TrashIcon className="h-4 w-4" />
                                                        </button>
                                                    </>
                                                )}
                                            </div>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>

                        {totalPages > 1 && (
                            <div className="flex items-center justify-between px-6 py-3 border-t border-base bg-subtle">
                                <p className="text-sm text-base-muted">Page {page} of {totalPages}</p>
                                <div className="flex gap-2">
                                    <button onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page === 1} className="p-1.5 rounded border border-base text-base-muted hover:bg-subtle disabled:opacity-40 disabled:cursor-not-allowed transition-colors">
                                        <ChevronLeftIcon className="h-4 w-4" />
                                    </button>
                                    <button onClick={() => setPage((p) => Math.min(totalPages, p + 1))} disabled={page === totalPages} className="p-1.5 rounded border border-base text-base-muted hover:bg-subtle disabled:opacity-40 disabled:cursor-not-allowed transition-colors">
                                        <ChevronRightIcon className="h-4 w-4" />
                                    </button>
                                </div>
                            </div>
                        )}
                    </div>
                )}
            </div>

            <Modal isOpen={activeModal?.type === 'create'} onClose={closeModal} title="Create User" size="md">
                <div className="space-y-4">
                    {formError && <Alert type="error" message={formError} />}
                    <div>
                        <label className="block text-sm font-medium text-base-secondary mb-1">Username</label>
                        <input type="text" value={createUsername} onChange={(e) => setCreateUsername(e.target.value)} placeholder="e.g. jsmith" className="w-full px-3 py-2 text-sm border border-base rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500" />
                    </div>
                    <div>
                        <label className="block text-sm font-medium text-base-secondary mb-1">Display Name</label>
                        <input type="text" value={createDisplayName} onChange={(e) => setCreateDisplayName(e.target.value)} placeholder="e.g. Jane Smith" className="w-full px-3 py-2 text-sm border border-base rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500" />
                    </div>
                    <div>
                        <label className="block text-sm font-medium text-base-secondary mb-1">Email</label>
                        <input type="email" value={createEmail} onChange={(e) => setCreateEmail(e.target.value)} placeholder="jane@example.com" className="w-full px-3 py-2 text-sm border border-base rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500" />
                    </div>
                    <div>
                        <div className="flex items-center justify-between mb-1">
                            <label className="text-sm font-medium text-base-secondary">Password</label>
                            <button type="button"
                                onClick={() => { setCreatePassword(generatePassword()); setShowPassword(true); }}
                                className="text-xs font-medium text-accent-text hover:opacity-75 transition-opacity">
                                ↻ Generate
                            </button>
                        </div>
                        <div className="relative">
                            <input
                                type={showPassword ? 'text' : 'password'}
                                value={createPassword}
                                onChange={(e) => setCreatePassword(e.target.value)}
                                placeholder="Min. 8 characters"
                                className="w-full px-3 py-2 pr-14 text-sm border border-base rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono"
                            />
                            <button type="button"
                                onClick={() => setShowPassword(p => !p)}
                                className="absolute right-3 top-1/2 -translate-y-1/2 text-xs text-base-muted hover:text-base-secondary transition-colors select-none">
                                {showPassword ? 'Hide' : 'Show'}
                            </button>
                        </div>
                    </div>
                    <div className="flex justify-end gap-3 pt-2">
                        <Button variant="ghost" onClick={closeModal} disabled={createMutation.isPending}>Cancel</Button>
                        <Button variant="primary" onClick={handleCreate} disabled={createMutation.isPending}>
                            {createMutation.isPending ? 'Creating…' : 'Create User'}
                        </Button>
                    </div>
                </div>
            </Modal>

            <Modal isOpen={activeModal?.type === 'edit'} onClose={closeModal} title="Edit User" size="md">
                <div className="space-y-4">
                    {formError && <Alert type="error" message={formError} />}
                    {activeModal?.type === 'edit' && (
                        <p className="text-sm text-base-muted">Editing <span className="font-medium text-base-secondary">@{activeModal.user.username}</span></p>
                    )}
                    <div>
                        <label className="block text-sm font-medium text-base-secondary mb-1">Display Name</label>
                        <input type="text" value={editDisplayName} onChange={(e) => setEditDisplayName(e.target.value)} className="w-full px-3 py-2 text-sm border border-base rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500" />
                    </div>
                    <div>
                        <label className="block text-sm font-medium text-base-secondary mb-1">Email</label>
                        <input type="email" value={editEmail} onChange={(e) => setEditEmail(e.target.value)} className="w-full px-3 py-2 text-sm border border-base rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500" />
                    </div>
                    <div>
                        <label className="flex items-center gap-2 cursor-pointer">
                            <input type="checkbox" checked={editActive} onChange={(e) => setEditActive(e.target.checked)} className="h-4 w-4 rounded border-base" style={{ accentColor: 'var(--accent)' }} />
                            <span className="text-sm font-medium text-base-secondary">Active</span>
                        </label>
                    </div>
                    <div className="flex justify-end gap-3 pt-2">
                        <Button variant="ghost" onClick={closeModal} disabled={updateMutation.isPending}>Cancel</Button>
                        <Button variant="primary" onClick={handleUpdate} disabled={updateMutation.isPending}>
                            {updateMutation.isPending ? 'Saving…' : 'Save Changes'}
                        </Button>
                    </div>
                </div>
            </Modal>

            <Modal isOpen={activeModal?.type === 'delete'} onClose={closeModal} title="Delete User" size="sm">
                <div className="space-y-4">
                    {activeModal?.type === 'delete' && (
                        <p className="text-sm text-base-secondary">
                            Delete <span className="font-semibold">@{activeModal.user.username}</span>? The user will be soft-deleted and can be restored within 30 days.
                        </p>
                    )}
                    <div className="flex justify-end gap-3 pt-2">
                        <Button variant="ghost" onClick={closeModal} disabled={deleteMutation.isPending}>Cancel</Button>
                        <Button variant="danger" onClick={handleDelete} disabled={deleteMutation.isPending}>
                            {deleteMutation.isPending ? 'Deleting…' : 'Delete User'}
                        </Button>
                    </div>
                </div>
            </Modal>

            <Modal isOpen={activeModal?.type === 'restore'} onClose={closeModal} title="Restore User" size="sm">
                <div className="space-y-4">
                    {activeModal?.type === 'restore' && (
                        <p className="text-sm text-base-secondary">
                            Restore <span className="font-semibold">@{activeModal.user.username}</span>? Their account will become active again.
                        </p>
                    )}
                    <div className="flex justify-end gap-3 pt-2">
                        <Button variant="ghost" onClick={closeModal} disabled={restoreMutation.isPending}>Cancel</Button>
                        <Button variant="primary" onClick={handleRestore} disabled={restoreMutation.isPending}>
                            {restoreMutation.isPending ? 'Restoring…' : 'Restore User'}
                        </Button>
                    </div>
                </div>
            </Modal>

            <Modal isOpen={activeModal?.type === 'roles'} onClose={closeModal} title="Manage Roles" size="md">
                <div className="space-y-4">
                    {formError && <Alert type="error" message={formError} />}
                    {activeModal?.type === 'roles' && (
                        <p className="text-sm text-base-muted">Roles for <span className="font-medium text-base-secondary">@{activeModal.user.username}</span></p>
                    )}
                    {rolesLoading ? (
                        <Loading />
                    ) : (
                        <div className="space-y-2">
                            {(allRoles as any[] ?? []).map((role: any) => (
                                <label key={role.id} className="flex items-start gap-3 p-3 rounded-lg border border-base hover:bg-subtle cursor-pointer transition-colors">
                                    <input
                                        type="checkbox"
                                        checked={selectedRoleIds.has(role.id)}
                                        onChange={() => toggleRoleId(role.id)}
                                        className="mt-0.5 h-4 w-4 rounded border-base"
                                        style={{ accentColor: 'var(--accent)' }}
                                    />
                                    <div>
                                        <p className="text-sm font-medium text-base-primary">{role.name}</p>
                                        {role.description && <p className="text-xs text-base-muted mt-0.5">{role.description}</p>}
                                    </div>
                                </label>
                            ))}
                        </div>
                    )}
                    <div className="flex justify-end gap-3 pt-2">
                        <Button variant="ghost" onClick={closeModal} disabled={updateRolesMutation.isPending}>Cancel</Button>
                        <Button variant="primary" onClick={handleSaveRoles} disabled={updateRolesMutation.isPending || rolesLoading}>
                            {updateRolesMutation.isPending ? 'Saving…' : 'Save Roles'}
                        </Button>
                    </div>
                </div>
            </Modal>
        </>
    );
};
