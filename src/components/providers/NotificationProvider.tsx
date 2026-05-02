import React from 'react';
import { useNotificationStore } from '../../store/notificationStore';
import { ToastComponent } from '../ui/Toast';

export const NotificationProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
    const { notifications, removeNotification } = useNotificationStore();

    return (
        <>
            {children}

            {/* Toast notifications container */}
            <div className="fixed top-4 right-4 z-50 space-y-2">
                {notifications.slice(0, 5).map((notification) => (
                    <ToastComponent
                        key={notification.id}
                        id={notification.id}
                        type={notification.type}
                        title={notification.title}
                        message={notification.message}
                        onClose={() => removeNotification(notification.id)}
                        persistent={notification.type === 'error' || notification.type === 'warning'}
                    />
                ))}
            </div>
        </>
    );
};