import { create } from 'zustand';
import { devtools, persist } from 'zustand/middleware';
import { AppNotification } from '../types';

interface NotificationState {
    notifications: AppNotification[];
    unreadCount: number;

    // Actions
    addNotification: (notification: Omit<AppNotification, 'id' | 'timestamp' | 'read'>) => void;
    removeNotification: (id: string) => void;
    markAsRead: (id: string) => void;
    markAllAsRead: () => void;
    clearAll: () => void;
    clearRead: () => void;

    // Getters
    getUnreadNotifications: () => AppNotification[];
    getNotificationsByType: (type: AppNotification['type']) => AppNotification[];
}

export const useNotificationStore = create<NotificationState>()(
    devtools(
        persist(
            (set, get) => ({
                notifications: [],
                unreadCount: 0,

                addNotification: (notificationData) => {
                    const notification: AppNotification = {
                        id: `notification_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
                        timestamp: new Date().toISOString(),
                        read: false,
                        ...notificationData,
                    };

                    set((state) => {
                        const newNotifications = [notification, ...state.notifications];
                        return {
                            notifications: newNotifications,
                            unreadCount: newNotifications.filter(n => !n.read).length,
                        };
                    });

                    // Auto-remove success notifications after 5 seconds
                    if (notification.type === 'success') {
                        setTimeout(() => {
                            get().removeNotification(notification.id);
                        }, 5000);
                    }

                    // Auto-remove info notifications after 8 seconds
                    if (notification.type === 'info') {
                        setTimeout(() => {
                            get().removeNotification(notification.id);
                        }, 8000);
                    }
                },

                removeNotification: (id) => {
                    set((state) => {
                        const newNotifications = state.notifications.filter(n => n.id !== id);
                        return {
                            notifications: newNotifications,
                            unreadCount: newNotifications.filter(n => !n.read).length,
                        };
                    });
                },

                markAsRead: (id) => {
                    set((state) => {
                        const newNotifications = state.notifications.map(n =>
                            n.id === id ? { ...n, read: true } : n
                        );
                        return {
                            notifications: newNotifications,
                            unreadCount: newNotifications.filter(n => !n.read).length,
                        };
                    });
                },

                markAllAsRead: () => {
                    set((state) => ({
                        notifications: state.notifications.map(n => ({ ...n, read: true })),
                        unreadCount: 0,
                    }));
                },

                clearAll: () => {
                    set({
                        notifications: [],
                        unreadCount: 0,
                    });
                },

                clearRead: () => {
                    set((state) => {
                        const newNotifications = state.notifications.filter(n => !n.read);
                        return {
                            notifications: newNotifications,
                            unreadCount: newNotifications.length,
                        };
                    });
                },

                getUnreadNotifications: () => {
                    return get().notifications.filter(n => !n.read);
                },

                getNotificationsByType: (type) => {
                    return get().notifications.filter(n => n.type === type);
                },
            }),
            {
                name: 'notification-store',
                partialize: (state) => ({
                    // Only persist notifications, not the computed unreadCount
                    notifications: state.notifications,
                }),
                onRehydrateStorage: () => (state) => {
                    // Recalculate unreadCount after rehydration
                    if (state) {
                        state.unreadCount = state.notifications.filter(n => !n.read).length;
                    }
                },
            }
        ),
        {
            name: 'notification-store',
        }
    )
);

// Hook for showing toast notifications
export const useToast = () => {
    const addNotification = useNotificationStore((state) => state.addNotification);

    return {
        success: (title: string, message?: string) => {
            addNotification({
                type: 'success',
                title,
                message: message || '',
            });
        },
        error: (title: string, message?: string) => {
            addNotification({
                type: 'error',
                title,
                message: message || '',
            });
        },
        warning: (title: string, message?: string) => {
            addNotification({
                type: 'warning',
                title,
                message: message || '',
            });
        },
        info: (title: string, message?: string) => {
            addNotification({
                type: 'info',
                title,
                message: message || '',
            });
        },
    };
};

// Hook for managing notification preferences
export const useNotificationPreferences = () => {
    const addNotification = useNotificationStore((state) => state.addNotification);

    const requestBrowserPermission = async () => {
        if ('Notification' in window) {
            const permission = await Notification.requestPermission();

            if (permission === 'granted') {
                addNotification({
                    type: 'success',
                    title: 'Browser Notifications Enabled',
                    message: 'You will now receive browser notifications.',
                });
            } else if (permission === 'denied') {
                addNotification({
                    type: 'warning',
                    title: 'Browser Notifications Blocked',
                    message: 'Please enable notifications in your browser settings.',
                });
            }

            return permission;
        }

        return 'unsupported';
    };

    const showBrowserNotification = (title: string, options?: NotificationOptions) => {
        if ('Notification' in window && Notification.permission === 'granted') {
            new Notification(title, {
                icon: '/favicon.ico',
                badge: '/favicon.ico',
                ...options,
            });
        }
    };

    return {
        requestBrowserPermission,
        showBrowserNotification,
        isSupported: 'Notification' in window,
        permission: 'Notification' in window ? Notification.permission : 'unsupported',
    };
};