import React from 'react';
import { useQuery } from '@tanstack/react-query';
import {
    UsersIcon,
    ShieldCheckIcon,
    ServerIcon,
    ChartBarIcon,
    ExclamationTriangleIcon,
    CheckCircleIcon,
    ClockIcon,
    CogIcon,
    DocumentTextIcon,
    KeyIcon,
    ShareIcon,
    EyeIcon
} from '@heroicons/react/24/outline';
import { apiService } from '../../services/api';
import { queryKeys } from '../../lib/queryClient';
import { useTranslation } from '../../lib/i18n';
import { useLocaleFormat } from '../../lib/i18n';
import { Button } from '../../components/ui/Button';
import { Loading } from '../../components/ui/Loading';
import { Alert } from '../../components/ui/Alert';

interface AdminStats {
    users: {
        total: number;
        active: number;
        inactive: number;
        newThisMonth: number;
    };
    secrets: {
        total: number;
        shared: number;
        private: number;
        byType: Record<string, number>;
    };
    system: {
        uptime: string;
        version: string;
        lastBackup: string;
        diskUsage: number;
        memoryUsage: number;
    };
    security: {
        failedLogins: number;
        suspiciousActivity: number;
        activeAlerts: number;
        lastSecurityScan: string;
    };
    activity: {
        dailyActiveUsers: number;
        secretsCreatedToday: number;
        sharesCreatedToday: number;
        apiCallsToday: number;
    };
}

interface SystemAlert {
    id: string;
    type: 'error' | 'warning' | 'info';
    title: string;
    message: string;
    timestamp: string;
    resolved: boolean;
}

const StatCard: React.FC<{
    title: string;
    value: string | number;
    subtitle?: string;
    icon: React.ComponentType<{ className?: string }>;
    color: 'blue' | 'green' | 'yellow' | 'red' | 'purple';
    trend?: { value: number; isPositive: boolean };
    onClick?: () => void;
}> = ({ title, value, subtitle, icon: Icon, color, trend, onClick }) => {
    const colorClasses = {
        blue: 'bg-blue-50 text-blue-600 dark:bg-blue-900/20 dark:text-blue-400',
        green: 'bg-green-50 text-green-600 dark:bg-green-900/20 dark:text-green-400',
        yellow: 'bg-yellow-50 text-yellow-600 dark:bg-yellow-900/20 dark:text-yellow-400',
        red: 'bg-red-50 text-red-600 dark:bg-red-900/20 dark:text-red-400',
        purple: 'bg-purple-50 text-purple-600 dark:bg-purple-900/20 dark:text-purple-400',
    };

    return (
        <div
            className={`bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6 ${onClick ? 'cursor-pointer hover:shadow-md transition-shadow' : ''
                }`}
            onClick={onClick}
        >
            <div className="flex items-center justify-between">
                <div className="flex-1">
                    <p className="text-sm font-medium text-gray-600 dark:text-gray-400">
                        {title}
                    </p>
                    <p className="text-3xl font-semibold text-gray-900 dark:text-white mt-2">
                        {typeof value === 'number' ? value.toLocaleString() : value}
                    </p>
                    {subtitle && (
                        <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                            {subtitle}
                        </p>
                    )}
                    {trend && (
                        <div className="flex items-center mt-2">
                            <span className={`text-sm font-medium ${trend.isPositive ? 'text-green-600' : 'text-red-600'
                                }`}>
                                {trend.isPositive ? '+' : ''}{trend.value}%
                            </span>
                            <span className="text-sm text-gray-500 dark:text-gray-400 ml-1">
                                vs last month
                            </span>
                        </div>
                    )}
                </div>
                <div className={`p-3 rounded-lg ${colorClasses[color]}`}>
                    <Icon className="h-6 w-6" />
                </div>
            </div>
        </div>
    );
};

const AlertCard: React.FC<{ alert: SystemAlert }> = ({ alert }) => {
    const { formatDateTime } = useLocaleFormat();

    const getAlertIcon = (type: SystemAlert['type']) => {
        switch (type) {
            case 'error':
                return <ExclamationTriangleIcon className="h-5 w-5 text-red-500" />;
            case 'warning':
                return <ExclamationTriangleIcon className="h-5 w-5 text-yellow-500" />;
            case 'info':
                return <CheckCircleIcon className="h-5 w-5 text-blue-500" />;
            default:
                return <ClockIcon className="h-5 w-5 text-gray-500" />;
        }
    };

    const getAlertColor = (type: SystemAlert['type']) => {
        switch (type) {
            case 'error':
                return 'border-red-200 bg-red-50 dark:border-red-800 dark:bg-red-900/20';
            case 'warning':
                return 'border-yellow-200 bg-yellow-50 dark:border-yellow-800 dark:bg-yellow-900/20';
            case 'info':
                return 'border-blue-200 bg-blue-50 dark:border-blue-800 dark:bg-blue-900/20';
            default:
                return 'border-gray-200 bg-gray-50 dark:border-gray-700 dark:bg-gray-700';
        }
    };

    return (
        <div className={`p-4 rounded-lg border ${getAlertColor(alert.type)}`}>
            <div className="flex items-start space-x-3">
                <div className="flex-shrink-0 mt-0.5">
                    {getAlertIcon(alert.type)}
                </div>
                <div className="flex-1">
                    <h4 className="text-sm font-medium text-gray-900 dark:text-white">
                        {alert.title}
                    </h4>
                    <p className="text-sm text-gray-600 dark:text-gray-300 mt-1">
                        {alert.message}
                    </p>
                    <p className="text-xs text-gray-500 dark:text-gray-400 mt-2">
                        {formatDateTime(alert.timestamp)}
                    </p>
                </div>
                {alert.resolved && (
                    <div className="flex-shrink-0">
                        <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">
                            Resolved
                        </span>
                    </div>
                )}
            </div>
        </div>
    );
};

export const AdminDashboardPage: React.FC = () => {
    const { t } = useTranslation();
    const { formatDateTime } = useLocaleFormat();

    // Fetch admin statistics
    const { data: stats, isLoading: statsLoading, error: statsError } = useQuery({
        queryKey: queryKeys.admin.stats(),
        queryFn: async (): Promise<AdminStats> => {
            // Mock admin stats - in real app this would come from the API
            await new Promise(resolve => setTimeout(resolve, 1000));

            return {
                users: {
                    total: 1247,
                    active: 1156,
                    inactive: 91,
                    newThisMonth: 23,
                },
                secrets: {
                    total: 8934,
                    shared: 2341,
                    private: 6593,
                    byType: {
                        password: 3421,
                        api_key: 2156,
                        certificate: 1234,
                        text: 1567,
                        json: 556,
                    },
                },
                system: {
                    uptime: '99.98%',
                    version: '2.1.4',
                    lastBackup: new Date(Date.now() - 1000 * 60 * 60 * 6).toISOString(),
                    diskUsage: 67.3,
                    memoryUsage: 45.2,
                },
                security: {
                    failedLogins: 12,
                    suspiciousActivity: 3,
                    activeAlerts: 2,
                    lastSecurityScan: new Date(Date.now() - 1000 * 60 * 60 * 24).toISOString(),
                },
                activity: {
                    dailyActiveUsers: 456,
                    secretsCreatedToday: 34,
                    sharesCreatedToday: 12,
                    apiCallsToday: 15678,
                },
            };
        },
        staleTime: 2 * 60 * 1000, // 2 minutes
    });

    // Fetch system alerts
    const { data: alerts } = useQuery({
        queryKey: ['admin', 'alerts'],
        queryFn: async (): Promise<SystemAlert[]> => {
            // Mock alerts - in real app this would come from the API
            await new Promise(resolve => setTimeout(resolve, 500));

            return [
                {
                    id: '1',
                    type: 'warning',
                    title: 'High Memory Usage',
                    message: 'System memory usage is above 80%. Consider scaling resources.',
                    timestamp: new Date(Date.now() - 1000 * 60 * 30).toISOString(),
                    resolved: false,
                },
                {
                    id: '2',
                    type: 'info',
                    title: 'Backup Completed',
                    message: 'Daily backup completed successfully at 02:00 UTC.',
                    timestamp: new Date(Date.now() - 1000 * 60 * 60 * 6).toISOString(),
                    resolved: true,
                },
                {
                    id: '3',
                    type: 'error',
                    title: 'Failed Login Attempts',
                    message: 'Multiple failed login attempts detected from IP 192.168.1.100.',
                    timestamp: new Date(Date.now() - 1000 * 60 * 60 * 2).toISOString(),
                    resolved: false,
                },
            ];
        },
        staleTime: 1 * 60 * 1000, // 1 minute
    });

    const handleNavigateToUsers = () => {
        // Navigation would be handled by router
        console.log('Navigate to user management');
    };

    const handleNavigateToSecurity = () => {
        // Navigation would be handled by router
        console.log('Navigate to security settings');
    };

    const handleNavigateToSystem = () => {
        // Navigation would be handled by router
        console.log('Navigate to system settings');
    };

    if (statsError) {
        return (
            <div className="p-6">
                <Alert
                    type="error"
                    title="Failed to load admin dashboard"
                    message="There was an error loading the admin dashboard data. Please try again."
                />
            </div>
        );
    }

    return (
        <div className="p-6 space-y-6">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-2xl font-semibold text-gray-900 dark:text-white">
                        {t('dashboard.title')} - Admin
                    </h1>
                    <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                        System administration and management overview
                    </p>
                </div>
                <div className="flex items-center space-x-3">
                    <Button
                        variant="outline"
                        onClick={handleNavigateToSystem}
                    >
                        <CogIcon className="h-4 w-4 mr-2" />
                        System Settings
                    </Button>
                    <Button
                        onClick={handleNavigateToSecurity}
                    >
                        <ShieldCheckIcon className="h-4 w-4 mr-2" />
                        Security Center
                    </Button>
                </div>
            </div>

            {/* Statistics Cards */}
            {statsLoading ? (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                    {Array.from({ length: 8 }).map((_, i) => (
                        <div key={i} className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
                            <Loading />
                        </div>
                    ))}
                </div>
            ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                    <StatCard
                        title="Total Users"
                        value={stats?.users.total || 0}
                        subtitle={`${stats?.users.active || 0} active`}
                        icon={UsersIcon}
                        color="blue"
                        trend={{ value: 8.2, isPositive: true }}
                        onClick={handleNavigateToUsers}
                    />
                    <StatCard
                        title="Total Secrets"
                        value={stats?.secrets.total || 0}
                        subtitle={`${stats?.secrets.shared || 0} shared`}
                        icon={KeyIcon}
                        color="green"
                        trend={{ value: 12.5, isPositive: true }}
                    />
                    <StatCard
                        title="System Uptime"
                        value={stats?.system.uptime || '0%'}
                        subtitle={`Version ${stats?.system.version || 'Unknown'}`}
                        icon={ServerIcon}
                        color="purple"
                    />
                    <StatCard
                        title="Security Alerts"
                        value={stats?.security.activeAlerts || 0}
                        subtitle={`${stats?.security.failedLogins || 0} failed logins`}
                        icon={ShieldCheckIcon}
                        color={stats?.security.activeAlerts ? 'red' : 'green'}
                        onClick={handleNavigateToSecurity}
                    />
                    <StatCard
                        title="Daily Active Users"
                        value={stats?.activity.dailyActiveUsers || 0}
                        subtitle="Today"
                        icon={ChartBarIcon}
                        color="blue"
                        trend={{ value: 5.3, isPositive: true }}
                    />
                    <StatCard
                        title="Secrets Created"
                        value={stats?.activity.secretsCreatedToday || 0}
                        subtitle="Today"
                        icon={KeyIcon}
                        color="green"
                    />
                    <StatCard
                        title="Shares Created"
                        value={stats?.activity.sharesCreatedToday || 0}
                        subtitle="Today"
                        icon={ShareIcon}
                        color="purple"
                    />
                    <StatCard
                        title="API Calls"
                        value={stats?.activity.apiCallsToday || 0}
                        subtitle="Today"
                        icon={DocumentTextIcon}
                        color="yellow"
                    />
                </div>
            )}

            {/* Main Content Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* System Health */}
                <div className="lg:col-span-2">
                    <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
                        <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
                            <h2 className="text-lg font-medium text-gray-900 dark:text-white">
                                System Health
                            </h2>
                        </div>
                        <div className="p-6">
                            {statsLoading ? (
                                <Loading />
                            ) : (
                                <div className="space-y-6">
                                    {/* Resource Usage */}
                                    <div>
                                        <h3 className="text-sm font-medium text-gray-900 dark:text-white mb-4">
                                            Resource Usage
                                        </h3>
                                        <div className="space-y-4">
                                            <div>
                                                <div className="flex items-center justify-between mb-2">
                                                    <span className="text-sm text-gray-600 dark:text-gray-400">
                                                        Memory Usage
                                                    </span>
                                                    <span className="text-sm font-medium text-gray-900 dark:text-white">
                                                        {stats?.system.memoryUsage}%
                                                    </span>
                                                </div>
                                                <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                                                    <div
                                                        className={`h-2 rounded-full ${(stats?.system.memoryUsage || 0) > 80
                                                                ? 'bg-red-500'
                                                                : (stats?.system.memoryUsage || 0) > 60
                                                                    ? 'bg-yellow-500'
                                                                    : 'bg-green-500'
                                                            }`}
                                                        style={{ width: `${stats?.system.memoryUsage || 0}%` }}
                                                    />
                                                </div>
                                            </div>
                                            <div>
                                                <div className="flex items-center justify-between mb-2">
                                                    <span className="text-sm text-gray-600 dark:text-gray-400">
                                                        Disk Usage
                                                    </span>
                                                    <span className="text-sm font-medium text-gray-900 dark:text-white">
                                                        {stats?.system.diskUsage}%
                                                    </span>
                                                </div>
                                                <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                                                    <div
                                                        className={`h-2 rounded-full ${(stats?.system.diskUsage || 0) > 80
                                                                ? 'bg-red-500'
                                                                : (stats?.system.diskUsage || 0) > 60
                                                                    ? 'bg-yellow-500'
                                                                    : 'bg-green-500'
                                                            }`}
                                                        style={{ width: `${stats?.system.diskUsage || 0}%` }}
                                                    />
                                                </div>
                                            </div>
                                        </div>
                                    </div>

                                    {/* System Info */}
                                    <div>
                                        <h3 className="text-sm font-medium text-gray-900 dark:text-white mb-4">
                                            System Information
                                        </h3>
                                        <div className="grid grid-cols-2 gap-4 text-sm">
                                            <div>
                                                <span className="text-gray-600 dark:text-gray-400">Version:</span>
                                                <span className="ml-2 font-medium text-gray-900 dark:text-white">
                                                    {stats?.system.version}
                                                </span>
                                            </div>
                                            <div>
                                                <span className="text-gray-600 dark:text-gray-400">Uptime:</span>
                                                <span className="ml-2 font-medium text-gray-900 dark:text-white">
                                                    {stats?.system.uptime}
                                                </span>
                                            </div>
                                            <div className="col-span-2">
                                                <span className="text-gray-600 dark:text-gray-400">Last Backup:</span>
                                                <span className="ml-2 font-medium text-gray-900 dark:text-white">
                                                    {stats?.system.lastBackup && formatDateTime(stats.system.lastBackup)}
                                                </span>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            )}
                        </div>
                    </div>
                </div>

                {/* System Alerts */}
                <div>
                    <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
                        <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
                            <div className="flex items-center justify-between">
                                <h2 className="text-lg font-medium text-gray-900 dark:text-white">
                                    System Alerts
                                </h2>
                                <Button variant="ghost" size="sm">
                                    <EyeIcon className="h-4 w-4 mr-2" />
                                    View All
                                </Button>
                            </div>
                        </div>
                        <div className="p-6">
                            {alerts && alerts.length > 0 ? (
                                <div className="space-y-4">
                                    {alerts.slice(0, 3).map((alert) => (
                                        <AlertCard key={alert.id} alert={alert} />
                                    ))}
                                </div>
                            ) : (
                                <div className="text-center py-8">
                                    <CheckCircleIcon className="h-12 w-12 text-green-500 mx-auto mb-4" />
                                    <p className="text-gray-500 dark:text-gray-400">
                                        No active alerts
                                    </p>
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            </div>

            {/* Quick Actions */}
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
                <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
                    <h2 className="text-lg font-medium text-gray-900 dark:text-white">
                        Quick Actions
                    </h2>
                </div>
                <div className="p-6">
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                        <Button
                            variant="outline"
                            className="flex items-center justify-center p-6 h-auto"
                            onClick={handleNavigateToUsers}
                        >
                            <div className="text-center">
                                <UsersIcon className="h-8 w-8 text-blue-500 mx-auto mb-2" />
                                <div className="font-medium text-gray-900 dark:text-white">
                                    Manage Users
                                </div>
                                <div className="text-sm text-gray-500 dark:text-gray-400">
                                    User accounts & roles
                                </div>
                            </div>
                        </Button>

                        <Button
                            variant="outline"
                            className="flex items-center justify-center p-6 h-auto"
                            onClick={handleNavigateToSecurity}
                        >
                            <div className="text-center">
                                <ShieldCheckIcon className="h-8 w-8 text-green-500 mx-auto mb-2" />
                                <div className="font-medium text-gray-900 dark:text-white">
                                    Security Center
                                </div>
                                <div className="text-sm text-gray-500 dark:text-gray-400">
                                    Security settings & logs
                                </div>
                            </div>
                        </Button>

                        <Button
                            variant="outline"
                            className="flex items-center justify-center p-6 h-auto"
                            onClick={handleNavigateToSystem}
                        >
                            <div className="text-center">
                                <CogIcon className="h-8 w-8 text-purple-500 mx-auto mb-2" />
                                <div className="font-medium text-gray-900 dark:text-white">
                                    System Settings
                                </div>
                                <div className="text-sm text-gray-500 dark:text-gray-400">
                                    Configuration & maintenance
                                </div>
                            </div>
                        </Button>

                        <Button
                            variant="outline"
                            className="flex items-center justify-center p-6 h-auto"
                        >
                            <div className="text-center">
                                <DocumentTextIcon className="h-8 w-8 text-orange-500 mx-auto mb-2" />
                                <div className="font-medium text-gray-900 dark:text-white">
                                    Audit Logs
                                </div>
                                <div className="text-sm text-gray-500 dark:text-gray-400">
                                    System activity & compliance
                                </div>
                            </div>
                        </Button>
                    </div>
                </div>
            </div>
        </div>
    );
};