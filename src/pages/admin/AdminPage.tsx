import React, { useState } from 'react';
import {
    MagnifyingGlassIcon,
    PlusIcon,
    ChevronLeftIcon,
    ChevronRightIcon,
    TrashIcon,
    PencilIcon,
    UserCircleIcon,
} from '@heroicons/react/24/outline';
import {
    useAdminUserList,
    useAdminCreateUser,
    useAdminUpdateUser,
    useAdminDeleteUser,
} from '../../features/admin';
import { Button } from '../../components/ui/Button';
import { Modal } from '../../components/ui/Modal';
import { Alert } from '../../components/ui/Alert';
import { Loading } from '../../components/ui/Loading';

interface APIUser {
    id: number;
    username: string;
    email: string;
    display_name: string;
    active: boolean;
    created_at: string;
    updated_at: string;
}

type ActiveModal =
    | null
    | { type: 'create' }
    | { type: 'edit'; user: APIUser }
    | { type: 'delete'; user: APIUser };

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

export const AdminPage: React.FC = () => {
    const PAGE_SIZE = 20;

    const [page, setPage] = useState(1);
    const [search, setSearch] = useState('');
    const [searchInput, setSearchInput] = useState('');
    const [activeModal, setActiveModal] = useState<ActiveModal>(null);
    const [formError, setFormError] = useState('');
    const [pageError, setPageError] = useState('');
    const [selected, setSelected] = useState<Set<number>>(new Set());
    const [bulkPending, setBulkPending] = useState(false);

    const [createUsername, setCreateUsername] = useState('');
    const [createEmail, setCreateEmail] = useState('');
    const [createDisplayName, setCreateDisplayName] = useState('');
    const [createPassword, setCreatePassword] = useState('');

    const [editEmail, setEditEmail] = useState('');
    const [editDisplayName, setEditDisplayName] = useState('');
    const [editActive, setEditActive] = useState(true);

    const { data, isLoading, isError } = useAdminUserList({ page, search, pageSize: PAGE_SIZE });

    const rawData = data as any;
    const users: APIUser[] = rawData?.users ?? [];
    const total: number = rawData?.total ?? 0;
    const totalPages: number = rawData?.total_pages ?? 1;

    const createMutation = useAdminCreateUser();
    const updateMutation = useAdminUpdateUser();
    const deleteMutation = useAdminDeleteUser();

    function closeModal() {
        setActiveModal(null);
        setFormError('');
        setCreateUsername(''); setCreateEmail(''); setCreateDisplayName(''); setCreatePassword('');
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
                        <h1 className="text-2xl font-bold text-gray-900">User Management</h1>
                        <p className="text-sm text-gray-500 mt-1">
                            {total > 0 ? `${total} user${total !== 1 ? 's' : ''}` : 'No users found'}
                        </p>
                    </div>
                    <div className="flex items-center gap-2">
                        {selected.size > 0 && (
                            <>
                                <span className="text-sm text-gray-500">{selected.size} selected</span>
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

                <form onSubmit={(e) => { e.preventDefault(); setSearch(searchInput); setPage(1); }} className="flex gap-2 mb-6">
                    <div className="relative flex-1">
                        <MagnifyingGlassIcon className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
                        <input
                            type="text"
                            placeholder="Search by username or email…"
                            value={searchInput}
                            onChange={(e) => setSearchInput(e.target.value)}
                            className="w-full pl-9 pr-4 py-2 text-sm border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        />
                    </div>
                    <Button type="submit" variant="secondary">Search</Button>
                    {search && (
                        <Button type="button" variant="ghost" onClick={() => { setSearchInput(''); setSearch(''); setPage(1); }}>Clear</Button>
                    )}
                </form>

                {isLoading ? (
                    <Loading className="py-20" />
                ) : isError ? (
                    <Alert type="error" title="Failed to load users" message="Check that the server is running and you have admin access." />
                ) : users.length === 0 ? (
                    <div className="text-center py-20 text-gray-500">
                        <UserCircleIcon className="h-12 w-12 mx-auto mb-3 text-gray-300" />
                        <p className="text-sm">{search ? 'No users match your search.' : 'No users yet.'}</p>
                    </div>
                ) : (
                    <div className="bg-white border border-gray-200 rounded-lg overflow-hidden shadow-sm">
                        <table className="min-w-full divide-y divide-gray-200">
                            <thead className="bg-gray-50">
                                <tr>
                                    <th className="px-4 py-3 w-10">
                                        <input type="checkbox" className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                                            checked={users.length > 0 && selected.size === users.length}
                                            onChange={toggleAll} />
                                    </th>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">User</th>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Email</th>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Created</th>
                                    <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                                </tr>
                            </thead>
                            <tbody className="bg-white divide-y divide-gray-100">
                                {users.map((user) => (
                                    <tr key={user.id} className={`hover:bg-gray-50 transition-colors ${selected.has(user.id) ? 'bg-blue-50' : ''}`}>
                                        <td className="px-4 py-4 w-10">
                                            <input type="checkbox" className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
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
                                                    <p className="text-sm font-medium text-gray-900">{user.display_name || user.username}</p>
                                                    <p className="text-xs text-gray-400">@{user.username}</p>
                                                </div>
                                            </div>
                                        </td>
                                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-600">{user.email}</td>
                                        <td className="px-6 py-4 whitespace-nowrap">
                                            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${user.active ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-600'}`}>
                                                {user.active ? 'Active' : 'Inactive'}
                                            </span>
                                        </td>
                                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-400">{formatDate(user.created_at)}</td>
                                        <td className="px-6 py-4 whitespace-nowrap text-right">
                                            <div className="flex items-center justify-end gap-2">
                                                <button onClick={() => openEdit(user)} className="p-1.5 text-gray-400 hover:text-blue-600 hover:bg-blue-50 rounded transition-colors" title="Edit user">
                                                    <PencilIcon className="h-4 w-4" />
                                                </button>
                                                <button onClick={() => setActiveModal({ type: 'delete', user })} className="p-1.5 text-gray-400 hover:text-red-600 hover:bg-red-50 rounded transition-colors" title="Delete user">
                                                    <TrashIcon className="h-4 w-4" />
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>

                        {totalPages > 1 && (
                            <div className="flex items-center justify-between px-6 py-3 border-t border-gray-100 bg-gray-50">
                                <p className="text-sm text-gray-500">Page {page} of {totalPages}</p>
                                <div className="flex gap-2">
                                    <button onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page === 1} className="p-1.5 rounded border border-gray-200 text-gray-500 hover:bg-gray-100 disabled:opacity-40 disabled:cursor-not-allowed transition-colors">
                                        <ChevronLeftIcon className="h-4 w-4" />
                                    </button>
                                    <button onClick={() => setPage((p) => Math.min(totalPages, p + 1))} disabled={page === totalPages} className="p-1.5 rounded border border-gray-200 text-gray-500 hover:bg-gray-100 disabled:opacity-40 disabled:cursor-not-allowed transition-colors">
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
                        <label className="block text-sm font-medium text-gray-700 mb-1">Username</label>
                        <input type="text" value={createUsername} onChange={(e) => setCreateUsername(e.target.value)} placeholder="e.g. jsmith" className="w-full px-3 py-2 text-sm border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500" />
                    </div>
                    <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">Display Name</label>
                        <input type="text" value={createDisplayName} onChange={(e) => setCreateDisplayName(e.target.value)} placeholder="e.g. Jane Smith" className="w-full px-3 py-2 text-sm border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500" />
                    </div>
                    <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">Email</label>
                        <input type="email" value={createEmail} onChange={(e) => setCreateEmail(e.target.value)} placeholder="jane@example.com" className="w-full px-3 py-2 text-sm border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500" />
                    </div>
                    <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">Password</label>
                        <input type="password" value={createPassword} onChange={(e) => setCreatePassword(e.target.value)} placeholder="Min. 8 characters" className="w-full px-3 py-2 text-sm border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500" />
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
                        <p className="text-sm text-gray-500">Editing <span className="font-medium text-gray-700">@{activeModal.user.username}</span></p>
                    )}
                    <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">Display Name</label>
                        <input type="text" value={editDisplayName} onChange={(e) => setEditDisplayName(e.target.value)} className="w-full px-3 py-2 text-sm border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500" />
                    </div>
                    <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">Email</label>
                        <input type="email" value={editEmail} onChange={(e) => setEditEmail(e.target.value)} className="w-full px-3 py-2 text-sm border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500" />
                    </div>
                    <div className="flex items-center gap-3">
                        <input id="edit-active" type="checkbox" checked={editActive} onChange={(e) => setEditActive(e.target.checked)} className="h-4 w-4 text-blue-600 border-gray-300 rounded" />
                        <label htmlFor="edit-active" className="text-sm font-medium text-gray-700">Active</label>
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
                        <p className="text-sm text-gray-600">
                            Are you sure you want to delete <span className="font-semibold text-gray-900">@{activeModal.user.username}</span>? This action cannot be undone.
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
        </>
    );
};
