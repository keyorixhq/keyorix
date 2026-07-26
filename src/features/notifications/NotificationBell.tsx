import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { BellIcon } from '@heroicons/react/24/outline';
import { useNotifications, useMarkNotificationRead, useMarkAllNotificationsRead } from './api';
import type { NotificationItem } from '../../services/notifications';

// timeAgo renders a compact relative time ("3m", "2h", "5d") from an ISO string.
function timeAgo(iso: string): string {
    const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
    if (s < 60) return 'just now';
    if (s < 3600) return `${Math.floor(s / 60)}m ago`;
    if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
    return `${Math.floor(s / 86400)}d ago`;
}

/**
 * ADR-024 header notification bell: shows an unread-count badge and a dropdown of
 * recent in-app notifications. Clicking one marks it read and navigates to its
 * linked context; "Mark all read" clears the badge. Polls via React Query.
 */
export const NotificationBell: React.FC = () => {
    const [open, setOpen] = useState(false);
    const navigate = useNavigate();
    const { data } = useNotifications();
    const markRead = useMarkNotificationRead();
    const markAll = useMarkAllNotificationsRead();

    const items = data?.notifications ?? [];
    const unread = data?.unread_count ?? 0;

    const onItem = (n: NotificationItem) => {
        if (!n.is_read) markRead.mutate(n.id);
        setOpen(false);
        if (n.link) navigate(n.link);
    };

    return (
        <div className="relative">
            <button
                type="button"
                onClick={() => setOpen((o) => !o)}
                className="p-2 rounded-md relative transition-colors focus:outline-hidden focus:ring-2 focus:ring-inset focus:ring-blue-500"
                style={{ color: 'var(--text-muted)' }}
                title="Notifications"
                aria-label={unread > 0 ? `Notifications (${unread} unread)` : 'Notifications'}
            >
                <BellIcon className="h-6 w-6" />
                {unread > 0 && (
                    <span
                        className="absolute -top-0.5 -right-0.5 min-w-[1.1rem] h-[1.1rem] px-1 rounded-full text-[0.65rem] font-semibold flex items-center justify-center"
                        style={{ backgroundColor: 'var(--error, #dc2626)', color: '#fff' }}
                    >
                        {unread > 9 ? '9+' : unread}
                    </span>
                )}
            </button>

            {open && (
                <>
                    {/* Click-outside backdrop. */}
                    <div className="fixed inset-0 z-40" onClick={() => setOpen(false)} aria-hidden="true" />
                    <div
                        className="absolute right-0 mt-2 w-80 max-h-[26rem] overflow-y-auto z-50 rounded-lg border shadow-lg"
                        style={{ backgroundColor: 'var(--bg-surface)', borderColor: 'var(--border)' }}
                        role="menu"
                    >
                        <div
                            className="flex items-center justify-between px-3 py-2 border-b sticky top-0"
                            style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}
                        >
                            <span className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
                                Notifications
                            </span>
                            {unread > 0 && (
                                <button
                                    type="button"
                                    onClick={() => markAll.mutate()}
                                    disabled={markAll.isPending}
                                    className="text-xs font-medium hover:opacity-75 disabled:opacity-50"
                                    style={{ color: 'var(--accent-text)' }}
                                >
                                    Mark all read
                                </button>
                            )}
                        </div>

                        {items.length === 0 ? (
                            <div className="px-3 py-8 text-center text-sm" style={{ color: 'var(--text-muted)' }}>
                                You’re all caught up.
                            </div>
                        ) : (
                            <ul>
                                {items.map((n) => (
                                    <li key={n.id}>
                                        <button
                                            type="button"
                                            onClick={() => onItem(n)}
                                            className="w-full text-left px-3 py-2.5 border-b hover:bg-subtle transition-colors flex gap-2"
                                            style={{ borderColor: 'var(--border)' }}
                                        >
                                            <span
                                                className="mt-1.5 h-2 w-2 rounded-full shrink-0"
                                                style={{ backgroundColor: n.is_read ? 'transparent' : 'var(--accent)' }}
                                                aria-hidden="true"
                                            />
                                            <span className="min-w-0">
                                                <span
                                                    className="block text-sm font-medium truncate"
                                                    style={{ color: 'var(--text-primary)' }}
                                                >
                                                    {n.title}
                                                </span>
                                                <span className="block text-xs" style={{ color: 'var(--text-muted)' }}>
                                                    {n.message}
                                                </span>
                                                <span
                                                    className="block text-[0.7rem] mt-0.5"
                                                    style={{ color: 'var(--text-muted)' }}
                                                >
                                                    {timeAgo(n.created_at)}
                                                </span>
                                            </span>
                                        </button>
                                    </li>
                                ))}
                            </ul>
                        )}
                    </div>
                </>
            )}
        </div>
    );
};
