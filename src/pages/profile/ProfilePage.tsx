import React, { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import {
    UserIcon,
    CogIcon,
    ShieldCheckIcon,
    BellIcon,
    GlobeAltIcon,
    PaintBrushIcon,
    KeyIcon,
    DevicePhoneMobileIcon
} from '@heroicons/react/24/outline';
import { useAuthStore } from '../../store/authStore';
import { usePreferencesStore } from '../../store/preferencesStore';
import { useForm } from '../../store/formStore';
import { apiService } from '../../services/api';
import { Button } from '../../components/ui/Button';
import { Input } from '../../components/ui/Input';
import { Dropdown } from '../../components/ui/Dropdown';
import { Alert } from '../../components/ui/Alert';
import { Loading } from '../../components/ui/Loading';

interface ProfileTabProps {
    activeTab: string;
    setActiveTab: (tab: string) => void;
}

const ProfileTabs: React.FC<ProfileTabProps> = ({ activeTab, setActiveTab }) => {
    const tabs = [
        { id: 'profile', label: 'Profile', icon: UserIcon },
        { id: 'security', label: 'Security', icon: ShieldCheckIcon },
        { id: 'preferences', label: 'Preferences', icon: CogIcon },
        { id: 'notifications', label: 'Notifications', icon: BellIcon },
    ];

    return (
        <div className="border-b border-gray-200 dark:border-gray-700">
            <nav className="-mb-px flex space-x-8">
                {tabs.map((tab) => {
                    const Icon = tab.icon;
                    return (
                        <button
                            key={tab.id}
                            onClick={() => setActiveTab(tab.id)}
                            className={`flex items-center py-4 px-1 border-b-2 font-medium text-sm ${activeTab === tab.id
                                    ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400 dark:hover:text-gray-300'
                                }`}
                        >
                            <Icon className="h-5 w-5 mr-2" />
                            {tab.label}
                        </button>
                    );
                })}
            </nav>
        </div>
    );
};

const ProfileTab: React.FC = () => {
    const { user } = useAuthStore();
    const form = useForm('profile-form');
    const queryClient = useQueryClient();

    // Initialize form with user data
    React.useEffect(() => {
        if (user) {
            form.initialize({
                username: user.username,
                email: user.email,
                role: user.role,
            });
        }
    }, [user, form]);

    // Update profile mutation
    const updateProfileMutation = useMutation({
        mutationFn: (data: { username: string; email: string }) => {
            // In real app, this would call the API
            return Promise.resolve({ ...user, ...data });
        },
        onSuccess: () => {
            // Update user in auth store and cache
            queryClient.invalidateQueries({ queryKey: ['auth', 'profile'] });
        },
    });

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        const values = form.getValues();

        form.setSubmitting(true);
        try {
            await updateProfileMutation.mutateAsync({
                username: values.username,
                email: values.email,
            });
        } catch (error) {
            // Error handling
        } finally {
            form.setSubmitting(false);
        }
    };

    const values = form.getValues();
    const errors = form.getErrors();
    const isSubmitting = form.isSubmitting();

    return (
        <div className="space-y-6">
            <div>
                <h3 className="text-lg font-medium text-gray-900 dark:text-white">
                    Profile Information
                </h3>
                <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                    Update your account profile information and email address.
                </p>
            </div>

            {updateProfileMutation.error && (
                <Alert
                    type="error"
                    title="Failed to update profile"
                    message="There was an error updating your profile. Please try again."
                />
            )}

            <form onSubmit={handleSubmit} className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div>
                        <Input
                            label="Username"
                            type="text"
                            value={values.username || ''}
                            onChange={(e) => form.setValues({ username: e.target.value })}
                            error={errors.username}
                            required
                        />
                    </div>
                    <div>
                        <Input
                            label="Email"
                            type="email"
                            value={values.email || ''}
                            onChange={(e) => form.setValues({ email: e.target.value })}
                            error={errors.email}
                            required
                        />
                    </div>
                </div>

                <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                        Role
                    </label>
                    <div className="text-sm text-gray-900 dark:text-white bg-gray-50 dark:bg-gray-700 px-3 py-2 rounded-md">
                        {user?.role || 'User'}
                    </div>
                    <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                        Your role is managed by administrators and cannot be changed.
                    </p>
                </div>

                <div className="flex justify-end">
                    <Button
                        type="submit"
                        disabled={isSubmitting || !form.isDirty()}
                    >
                        {isSubmitting && <Loading size="sm" className="mr-2" />}
                        Save Changes
                    </Button>
                </div>
            </form>
        </div>
    );
};

const SecurityTab: React.FC = () => {
    const form = useForm('security-form');
    const [showCurrentPassword, setShowCurrentPassword] = useState(false);
    const [showNewPassword, setShowNewPassword] = useState(false);

    // Initialize form
    React.useEffect(() => {
        form.initialize({
            currentPassword: '',
            newPassword: '',
            confirmPassword: '',
        });
    }, [form]);

    // Change password mutation
    const changePasswordMutation = useMutation({
        mutationFn: (data: { currentPassword: string; newPassword: string }) => {
            // In real app, this would call the API
            return Promise.resolve();
        },
    });

    const handlePasswordChange = async (e: React.FormEvent) => {
        e.preventDefault();
        const values = form.getValues();

        // Validate passwords match
        if (values.newPassword !== values.confirmPassword) {
            form.setErrors({ confirmPassword: 'Passwords do not match' });
            return;
        }

        form.setSubmitting(true);
        try {
            await changePasswordMutation.mutateAsync({
                currentPassword: values.currentPassword,
                newPassword: values.newPassword,
            });

            // Reset form on success
            form.reset();
        } catch (error) {
            // Error handling
        } finally {
            form.setSubmitting(false);
        }
    };

    const values = form.getValues();
    const errors = form.getErrors();
    const isSubmitting = form.isSubmitting();

    return (
        <div className="space-y-8">
            {/* Change Password */}
            <div>
                <h3 className="text-lg font-medium text-gray-900 dark:text-white">
                    Change Password
                </h3>
                <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                    Update your password to keep your account secure.
                </p>

                {changePasswordMutation.error && (
                    <Alert
                        type="error"
                        title="Failed to change password"
                        message="There was an error changing your password. Please try again."
                    />
                )}

                <form onSubmit={handlePasswordChange} className="mt-6 space-y-6">
                    <div>
                        <Input
                            label="Current Password"
                            type={showCurrentPassword ? 'text' : 'password'}
                            value={values.currentPassword || ''}
                            onChange={(e) => form.setValues({ currentPassword: e.target.value })}
                            error={errors.currentPassword}
                            required
                        />
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                        <div>
                            <Input
                                label="New Password"
                                type={showNewPassword ? 'text' : 'password'}
                                value={values.newPassword || ''}
                                onChange={(e) => form.setValues({ newPassword: e.target.value })}
                                error={errors.newPassword}
                                required
                            />
                        </div>
                        <div>
                            <Input
                                label="Confirm New Password"
                                type={showNewPassword ? 'text' : 'password'}
                                value={values.confirmPassword || ''}
                                onChange={(e) => form.setValues({ confirmPassword: e.target.value })}
                                error={errors.confirmPassword}
                                required
                            />
                        </div>
                    </div>

                    <div className="flex justify-end">
                        <Button
                            type="submit"
                            disabled={isSubmitting}
                        >
                            {isSubmitting && <Loading size="sm" className="mr-2" />}
                            <KeyIcon className="h-4 w-4 mr-2" />
                            Change Password
                        </Button>
                    </div>
                </form>
            </div>

            {/* Two-Factor Authentication */}
            <div className="border-t border-gray-200 dark:border-gray-700 pt-8">
                <h3 className="text-lg font-medium text-gray-900 dark:text-white">
                    Two-Factor Authentication
                </h3>
                <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                    Add an extra layer of security to your account.
                </p>

                <div className="mt-6 bg-gray-50 dark:bg-gray-700 rounded-lg p-6">
                    <div className="flex items-center justify-between">
                        <div className="flex items-center">
                            <DevicePhoneMobileIcon className="h-8 w-8 text-gray-400 mr-4" />
                            <div>
                                <h4 className="text-sm font-medium text-gray-900 dark:text-white">
                                    Authenticator App
                                </h4>
                                <p className="text-sm text-gray-500 dark:text-gray-400">
                                    Not configured
                                </p>
                            </div>
                        </div>
                        <Button variant="outline">
                            Set Up
                        </Button>
                    </div>
                </div>
            </div>

            {/* Active Sessions */}
            <div className="border-t border-gray-200 dark:border-gray-700 pt-8">
                <h3 className="text-lg font-medium text-gray-900 dark:text-white">
                    Active Sessions
                </h3>
                <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                    Manage your active sessions across different devices.
                </p>

                <div className="mt-6 space-y-4">
                    <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                        <div className="flex items-center justify-between">
                            <div>
                                <h4 className="text-sm font-medium text-gray-900 dark:text-white">
                                    Current Session
                                </h4>
                                <p className="text-sm text-gray-500 dark:text-gray-400">
                                    Chrome on macOS • 192.168.1.100
                                </p>
                                <p className="text-xs text-gray-400 dark:text-gray-500">
                                    Last active: Now
                                </p>
                            </div>
                            <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">
                                Current
                            </span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

const PreferencesTab: React.FC = () => {
    const {
        language,
        timezone,
        theme,
        setLanguage,
        setTimezone,
        setTheme,
    } = usePreferencesStore();

    const LANGUAGE_OPTIONS = [
        { value: 'en', label: 'English' },
        { value: 'es', label: 'Español' },
        { value: 'fr', label: 'Français' },
        { value: 'ru', label: 'Русский' },
    ];

    const THEME_OPTIONS = [
        { value: 'light', label: 'Light' },
        { value: 'dark', label: 'Dark' },
        { value: 'system', label: 'System' },
    ];

    const TIMEZONE_OPTIONS = [
        { value: 'UTC', label: 'UTC' },
        { value: 'America/New_York', label: 'Eastern Time' },
        { value: 'America/Chicago', label: 'Central Time' },
        { value: 'America/Denver', label: 'Mountain Time' },
        { value: 'America/Los_Angeles', label: 'Pacific Time' },
        { value: 'Europe/London', label: 'London' },
        { value: 'Europe/Paris', label: 'Paris' },
        { value: 'Asia/Tokyo', label: 'Tokyo' },
    ];

    return (
        <div className="space-y-8">
            {/* Language & Region */}
            <div>
                <h3 className="text-lg font-medium text-gray-900 dark:text-white">
                    Language & Region
                </h3>
                <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                    Customize your language and regional preferences.
                </p>

                <div className="mt-6 grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                            <GlobeAltIcon className="h-4 w-4 inline mr-2" />
                            Language
                        </label>
                        <Dropdown
                            value={language}
                            onChange={setLanguage}
                            options={LANGUAGE_OPTIONS}
                        />
                    </div>
                    <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                            Timezone
                        </label>
                        <Dropdown
                            value={timezone}
                            onChange={setTimezone}
                            options={TIMEZONE_OPTIONS}
                        />
                    </div>
                </div>
            </div>

            {/* Appearance */}
            <div className="border-t border-gray-200 dark:border-gray-700 pt-8">
                <h3 className="text-lg font-medium text-gray-900 dark:text-white">
                    Appearance
                </h3>
                <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                    Customize how the interface looks and feels.
                </p>

                <div className="mt-6">
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                        <PaintBrushIcon className="h-4 w-4 inline mr-2" />
                        Theme
                    </label>
                    <Dropdown
                        value={theme}
                        onChange={setTheme}
                        options={THEME_OPTIONS}
                    />
                    <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                        System theme will automatically switch between light and dark based on your system preferences.
                    </p>
                </div>
            </div>
        </div>
    );
};

const NotificationsTab: React.FC = () => {
    const { notifications, setNotificationSettings } = usePreferencesStore();

    const handleToggle = (key: keyof typeof notifications) => {
        setNotificationSettings({
            [key]: !notifications[key],
        });
    };

    return (
        <div className="space-y-8">
            <div>
                <h3 className="text-lg font-medium text-gray-900 dark:text-white">
                    Notification Preferences
                </h3>
                <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                    Choose how you want to be notified about important events.
                </p>
            </div>

            <div className="space-y-6">
                <div className="flex items-center justify-between">
                    <div>
                        <h4 className="text-sm font-medium text-gray-900 dark:text-white">
                            Email Notifications
                        </h4>
                        <p className="text-sm text-gray-500 dark:text-gray-400">
                            Receive notifications via email
                        </p>
                    </div>
                    <button
                        type="button"
                        onClick={() => handleToggle('email')}
                        className={`relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 ${notifications.email ? 'bg-blue-600' : 'bg-gray-200 dark:bg-gray-700'
                            }`}
                    >
                        <span
                            className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${notifications.email ? 'translate-x-5' : 'translate-x-0'
                                }`}
                        />
                    </button>
                </div>

                <div className="flex items-center justify-between">
                    <div>
                        <h4 className="text-sm font-medium text-gray-900 dark:text-white">
                            Browser Notifications
                        </h4>
                        <p className="text-sm text-gray-500 dark:text-gray-400">
                            Show notifications in your browser
                        </p>
                    </div>
                    <button
                        type="button"
                        onClick={() => handleToggle('browser')}
                        className={`relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 ${notifications.browser ? 'bg-blue-600' : 'bg-gray-200 dark:bg-gray-700'
                            }`}
                    >
                        <span
                            className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${notifications.browser ? 'translate-x-5' : 'translate-x-0'
                                }`}
                        />
                    </button>
                </div>

                <div className="flex items-center justify-between">
                    <div>
                        <h4 className="text-sm font-medium text-gray-900 dark:text-white">
                            Sharing Notifications
                        </h4>
                        <p className="text-sm text-gray-500 dark:text-gray-400">
                            Get notified when secrets are shared with you
                        </p>
                    </div>
                    <button
                        type="button"
                        onClick={() => handleToggle('sharing')}
                        className={`relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 ${notifications.sharing ? 'bg-blue-600' : 'bg-gray-200 dark:bg-gray-700'
                            }`}
                    >
                        <span
                            className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${notifications.sharing ? 'translate-x-5' : 'translate-x-0'
                                }`}
                        />
                    </button>
                </div>

                <div className="flex items-center justify-between">
                    <div>
                        <h4 className="text-sm font-medium text-gray-900 dark:text-white">
                            Security Alerts
                        </h4>
                        <p className="text-sm text-gray-500 dark:text-gray-400">
                            Important security notifications and alerts
                        </p>
                    </div>
                    <button
                        type="button"
                        onClick={() => handleToggle('security')}
                        className={`relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 ${notifications.security ? 'bg-blue-600' : 'bg-gray-200 dark:bg-gray-700'
                            }`}
                    >
                        <span
                            className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${notifications.security ? 'translate-x-5' : 'translate-x-0'
                                }`}
                        />
                    </button>
                </div>
            </div>
        </div>
    );
};

export const ProfilePage: React.FC = () => {
    const [activeTab, setActiveTab] = useState('profile');

    const renderTabContent = () => {
        switch (activeTab) {
            case 'profile':
                return <ProfileTab />;
            case 'security':
                return <SecurityTab />;
            case 'preferences':
                return <PreferencesTab />;
            case 'notifications':
                return <NotificationsTab />;
            default:
                return <ProfileTab />;
        }
    };

    return (
        <div className="p-6 max-w-4xl mx-auto">
            <div className="mb-8">
                <h1 className="text-2xl font-semibold text-gray-900 dark:text-white">
                    Account Settings
                </h1>
                <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                    Manage your account settings and preferences.
                </p>
            </div>

            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
                <ProfileTabs activeTab={activeTab} setActiveTab={setActiveTab} />
                <div className="p-6">
                    {renderTabContent()}
                </div>
            </div>
        </div>
    );
};