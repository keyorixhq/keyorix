import { describe, it, expect, beforeEach } from 'vitest';
import { useUIStore } from '../uiStore';
import { useFormStore } from '../formStore';
import { usePreferencesStore } from '../preferencesStore';
import { useAppStore } from '../appStore';
import { useNotificationStore } from '../notificationStore';

describe('Store Tests', () => {
    beforeEach(() => {
        // Reset all stores before each test
        useUIStore.getState().reset();
        usePreferencesStore.getState().resetToDefaults();
        useAppStore.getState().reset();
        useNotificationStore.getState().clearAll();
    });

    describe('UI Store', () => {
        it('should manage sidebar state', () => {
            const store = useUIStore.getState();

            expect(store.sidebarOpen).toBe(true);

            store.setSidebarOpen(false);
            expect(useUIStore.getState().sidebarOpen).toBe(false);

            store.toggleSidebar();
            expect(useUIStore.getState().sidebarOpen).toBe(true);
        });

        it('should manage modal state', () => {
            const store = useUIStore.getState();

            expect(store.activeModal).toBe(null);

            store.openModal('test-modal', { data: 'test' });
            const state = useUIStore.getState();
            expect(state.activeModal).toBe('test-modal');
            expect(state.modalData).toEqual({ data: 'test' });

            store.closeModal();
            expect(useUIStore.getState().activeModal).toBe(null);
        });

        it('should manage selected items', () => {
            const store = useUIStore.getState();

            expect(store.selectedItems.size).toBe(0);

            store.toggleSelectedItem('item1');
            expect(useUIStore.getState().selectedItems.has('item1')).toBe(true);

            store.toggleSelectedItem('item1');
            expect(useUIStore.getState().selectedItems.has('item1')).toBe(false);
        });
    });

    describe('Form Store', () => {
        it('should initialize and manage forms', () => {
            const store = useFormStore.getState();
            const formId = 'test-form';
            const initialValues = { name: 'test', email: 'test@example.com' };

            store.initializeForm(formId, initialValues);

            const form = useFormStore.getState().forms[formId];
            expect(form).toBeDefined();
            expect(form.name.value).toBe('test');
            expect(form.email.value).toBe('test@example.com');
        });

        it('should manage field values and validation', () => {
            const store = useFormStore.getState();
            const formId = 'test-form';

            store.initializeForm(formId, { name: '' });

            store.setFieldValue(formId, 'name', 'John');
            expect(useFormStore.getState().forms[formId].name.value).toBe('John');
            expect(useFormStore.getState().forms[formId].name.dirty).toBe(true);

            store.setFieldError(formId, 'name', 'Name is required');
            expect(useFormStore.getState().forms[formId].name.error).toBe('Name is required');
        });

        it('should validate form state', () => {
            const store = useFormStore.getState();
            const formId = 'test-form';

            store.initializeForm(formId, { name: 'test' });

            expect(store.isFormValid(formId)).toBe(true);

            store.setFieldError(formId, 'name', 'Error');
            expect(useFormStore.getState().isFormValid(formId)).toBe(false);
        });
    });

    describe('Preferences Store', () => {
        it('should manage theme preferences', () => {
            const store = usePreferencesStore.getState();

            expect(store.theme).toBe('system');

            store.setTheme('dark');
            expect(usePreferencesStore.getState().theme).toBe('dark');
        });

        it('should manage language preferences', () => {
            const store = usePreferencesStore.getState();

            expect(store.language).toBe('en');

            store.setLanguage('es');
            expect(usePreferencesStore.getState().language).toBe('es');
        });

        it('should manage notification settings', () => {
            const store = usePreferencesStore.getState();

            store.setNotificationSettings({ email: false });
            expect(usePreferencesStore.getState().notifications.email).toBe(false);
            expect(usePreferencesStore.getState().notifications.browser).toBe(true);
        });
    });

    describe('App Store', () => {
        it('should manage application state', () => {
            const store = useAppStore.getState();

            expect(store.version).toBe('1.0.0');
            expect(store.initializing).toBe(true);

            store.setInitializing(false);
            expect(useAppStore.getState().initializing).toBe(false);
        });

        it('should manage feature flags', () => {
            const store = useAppStore.getState();

            store.setFeature('testFeature', true);
            expect(store.isFeatureEnabled('testFeature')).toBe(true);

            store.toggleFeature('testFeature');
            expect(useAppStore.getState().isFeatureEnabled('testFeature')).toBe(false);
        });

        it('should manage global search state', () => {
            const store = useAppStore.getState();

            expect(store.globalSearchOpen).toBe(false);

            store.setGlobalSearchOpen(true);
            expect(useAppStore.getState().globalSearchOpen).toBe(true);

            store.setGlobalSearchQuery('test query');
            expect(useAppStore.getState().globalSearchQuery).toBe('test query');
        });
    });

    describe('Notification Store', () => {
        it('should add and manage notifications', () => {
            const store = useNotificationStore.getState();

            expect(store.notifications.length).toBe(0);

            store.addNotification({
                type: 'success',
                title: 'Test',
                message: 'Test message'
            });

            const notifications = useNotificationStore.getState().notifications;
            expect(notifications.length).toBe(1);
            expect(notifications[0].type).toBe('success');
            expect(notifications[0].title).toBe('Test');
        });

        it('should mark notifications as read', () => {
            const store = useNotificationStore.getState();

            store.addNotification({
                type: 'info',
                title: 'Test',
                message: 'Test message'
            });

            const notification = useNotificationStore.getState().notifications[0];
            expect(notification.read).toBe(false);

            store.markAsRead(notification.id);
            expect(useNotificationStore.getState().notifications[0].read).toBe(true);
        });

        it('should count unread notifications', () => {
            const store = useNotificationStore.getState();

            store.addNotification({
                type: 'info',
                title: 'Test 1',
                message: 'Test message 1'
            });

            store.addNotification({
                type: 'warning',
                title: 'Test 2',
                message: 'Test message 2'
            });

            expect(store.getUnreadCount()).toBe(2);

            const notifications = useNotificationStore.getState().notifications;
            store.markAsRead(notifications[0].id);

            expect(useNotificationStore.getState().getUnreadCount()).toBe(1);
        });
    });
});