import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
    ClockIcon,
    KeyIcon,
    ShareIcon,
    EyeIcon,
    PencilIcon,
    TrashIcon,
    UserIcon,
    UserGroupIcon,
    ShieldCheckIcon,
    ExclamationTriangleIcon,
    MagnifyingGlassIcon,
    FunnelIcon,
    CalendarIcon
} from '@heroicons/react/24/outline';
import { apiService } from '../../services/api';
import { usePreferencesStore } from '../../store/preferencesStore';
import { ActivityItem } from '../../types';
import { Button } from '../ui/Button';
import { Input } from '../ui/Input';
import { Dropdown } from '../ui/Dropdown';
import { Loading } from '../ui/Loading';
import { Alert } from '../ui/Alert';

interface ActivityTimelineProps {
    secretId?: number;
    userId?: number;
    limit?: number;
    showFilters?: boolean;
}

interface ExtendedActivityItem extends ActivityItem {
    category: 'secret' | 'sharing' | 'security' | 'system';
    severity: 'low' | 'medium' | 'high' | 'critical';
    metadata?: Record<string, any>;
    ipAddress?: string;
    userAgent?: string;
}

const ACTIVITY_TYPES = [
    { value: 'all', label: 'All Activities' },
    { value: 'created', label: 'Created' },
    { value: 'updated', label: 'Updated' },
    { value: 'shared', label: 'Shared' },
    { value: 'accessed', label: 'Accessed' },
    { value: 'deleted', label: 'Deleted' },
];

const ACTIVITY_CATEGORIES = [
    { value: 'all', label: 'All Categories' },
    { value: 'secret', label: 'Secret Management' },
    { value: 'sharing', label: 'Sharing' },
    { value: 'security', label: 'Security' },
    { value: 'system', label: 'System' },
];

const TIME_RANGES = [
    { value: '1h', label: 'Last hour' },
    { value: '24h', label: 'Last 24 hours' },
    { value: '7d', label: 'Last 7 days' },
    { value: '30d', label: 'Last 30 days' },
];

export const ActivityTimeline: React.FC<ActivityTimelineProps> = ({
    secretId,
    userId,
    limit = 50,
    showFilters = true
}) => {
    const { getFormattedDate, getFormattedTime } = usePreferencesStore();

    // Filter state
    const [filters, setFilters] = useState({
        search: '',
        type: 'all',
        category: 'all',
        timeRange: '24h',
    });

    // Fetch activity data
    const { data: activityData, isLoading, error, refetch } = useQuery({
        queryKey: ['activity', 'timeline', { secretId, userId, ...filters, limit }],
        queryFn: async () => {
            // Mock activity data - in real app this would come from the API
            await new Promise(resolve => setTimeout(resolve, 800));

            const mockActivities: ExtendedActivityItem[] = [
                {
                    id: 1,
                    type: 'created',
                    secretName: 'database-password',
                    timestamp: new Date(Date.now() - 1000 * 60 * 30).toISOString(), // 30 minutes ago
                    actor: 'john.doe@company.com',
                    category: 'secret',
                    severity: 'low',
                    metadata: { namespace: 'production', type: 'password' },
                    ipAddress: '192.168.1.100',
                },
                {
                    id: 2,
                    type: 'shared',
                    secretName: 'api-key-stripe',
                    timestamp: new Date(Date.now() - 1000 * 60 * 60 * 2).toISOString(), // 2 hours ago
                    actor: 'jane.smith@company.com',
                    category: 'sharing',
                    severity: 'medium',
                    metadata: { recipientType: 'group', recipientName: 'DevOps Team', permission: 'read' },
                    ipAddress: '192.168.1.101',
                },
                {
                    id: 3,
                    type: 'accessed',
                    secretName: 'database-password',
                    timestamp: new Date(Date.now() - 1000 * 60 * 60 * 4).toISOString(), // 4 hours ago
                    actor: 'bob.wilson@company.com',
                    category: 'secret',
                    severity: 'low',
                    metadata: { accessMethod: 'web', duration: '5s' },
                    ipAddress: '192.168.1.102',
                },
                {
                    id: 4,
                    type: 'updated',
                    secretName: 'ssl-certificate',
                    timestamp: new Date(Date.now() - 1000 * 60 * 60 * 6).toISOString(), // 6 hours ago
                    actor: 'admin@company.com',
                    category: 'security',
                    severity: 'high',
                    metadata: { field: 'value', reason: 'certificate renewal' },
                    ipAddress: '192.168.1.1',
                },
                {
                    id: 5,
                    type: 'accessed',
                    secretName: 'api-key-stripe',
                    timestamp: new Date(Date.now() - 1000 * 60 * 60 * 8).toISOString(), // 8 hours ago
                    actor: 'system@company.com',
                    category: 'system',
                    severity: 'low',
                    metadata: { accessMethod: 'api', automated: true },
                    ipAddress: '10.0.0.1',
                },
                {
                    id: 6,
                    type: 'shared',
                    secretName: 'database-password',
                    timestamp: new Date(Date.now() - 1000 * 60 * 60 * 12).toISOString(), // 12 hours ago
                    actor: 'john.doe@company.com',
                    category: 'sharing',
                    severity: 'medium',
                    metadata: { recipientType: 'user', recipientName: 'Alice Johnson', permission: 'write' },
                    ipAddress: '192.168.1.100',
                },
            ];

            // Apply filters
            let filteredActivities = mockActivities;

            if (filters.search) {
                const searchLower = filters.search.toLowerCase();
                filteredActivities = filteredActivities.filter(activity =>
                    activity.secretName.toLowerCase().includes(searchLower) ||
                    activity.actor.toLowerCase().includes(searchLower)
                );
            }

            if (filters.type !== 'all') {
                filteredActivities = filteredActivities.filter(activity => activity.type === filters.type);
            }

            if (filters.category !== 'all') {
                filteredActivities = filteredActivities.filter(activity => activity.category === filters.category);
            }

            return filteredActivities.slice(0, limit);
        },
        staleTime: 30 * 1000, // 30 seconds
    });

    const getActivityIcon = (activity: ExtendedActivityItem) => {
        const iconClass = "h-5 w-5";

        switch (activity.type) {
            case 'created':
                return <KeyIcon className={`${iconClass} text-green-500`} />;
            case 'updated':
                return <PencilIcon className={`${iconClass} text-blue-500`} />;
            case 'shared':
                return <ShareIcon className={`${iconClass} text-purple-500`} />;
            case 'accessed':
                return <EyeIcon className={`${iconClass} text-orange-500`} />;
            case 'deleted':
                return <TrashIcon className={`${iconClass} text-red-500`} />;
            default:
                return <ClockIcon className={`${iconClass} text-gray-500`} />;
        }
    };

    const getSeverityColor = (severity: ExtendedActivityItem['severity']) => {
        switch (severity) {
            case 'critical':
                return 'border-red-500 bg-red-50 dark:bg-red-900/20';
            case 'high':
                return 'border-orange-500 bg-orange-50 dark:bg-orange-900/20';
            case 'medium':
                return 'border-yellow-500 bg-yellow-50 dark:bg-yellow-900/20';
            default:
                return 'border-gray-200 bg-gray-50 dark:border-gray-700 dark:bg-gray-700/50';
        }
    };

    const getSeverityIcon = (severity: ExtendedActivityItem['severity']) => {
        switch (severity) {
            case 'critical':
            case 'high':
                return <ExclamationTriangleIcon className="h-4 w-4 text-red-500" />;
            case 'medium':
                return <ShieldCheckIcon className="h-4 w-4 text-yellow-500" />;
            default:
                return null;
        }
    };

    const getActivityDescription = (activity: ExtendedActivityItem) => {
        const baseText = `${activity.type} secret "${activity.secretName}"`;

        if (activity.metadata) {
            switch (activity.type) {
                case 'shared':
                    return `${baseText} with ${activity.metadata.recipientName} (${activity.metadata.permission} access)`;
                case 'accessed':
                    return `${baseText} via ${activity.metadata.accessMethod}${activity.metadata.automated ? ' (automated)' : ''}`;
                case 'updated':
                    return `${baseText} - ${activity.metadata.reason || 'field updated'}`;
                default:
                    return baseText;
            }
        }

        return baseText;
    };

    const handleFilterChange = (key: string, value: string) => {
        setFilters(prev => ({ ...prev, [key]: value }));
    };

    if (error) {
        return (
            <Alert
                type="error"
                title="Failed to load activity"
                message="There was an error loading the activity timeline. Please try again."
                action={
                    <Button variant="outline" size="sm" onClick={() => refetch()}>
                        Retry
                    </Button>
                }
            />
        );
    }

    return (
        <div className="space-y-6">
            {/* Filters */}
            {showFilters && (
                <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                        <div>
                            <Input
                                type="text"
                                placeholder="Search activities..."
                                value={filters.search}
                                onChange={(e) => handleFilterChange('search', e.target.value)}
                                icon={MagnifyingGlassIcon}
                            />
                        </div>
                        <div>
                            <Dropdown
                                value={filters.type}
                                onChange={(value) => handleFilterChange('type', value)}
                                options={ACTIVITY_TYPES}
                                placeholder="Activity Type"
                            />
                        </div>
                        <div>
                            <Dropdown
                                value={filters.category}
                                onChange={(value) => handleFilterChange('category', value)}
                                options={ACTIVITY_CATEGORIES}
                                placeholder="Category"
                                icon={FunnelIcon}
                            />
                        </div>
                        <div>
                            <Dropdown
                                value={filters.timeRange}
                                onChange={(value) => handleFilterChange('timeRange', value)}
                                options={TIME_RANGES}
                                placeholder="Time Range"
                                icon={CalendarIcon}
                            />
                        </div>
                    </div>
                </div>
            )}

            {/* Timeline */}
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
                <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
                    <div className="flex items-center justify-between">
                        <h2 className="text-lg font-medium text-gray-900 dark:text-white">
                            Activity Timeline
                        </h2>
                        <Button variant="ghost" size="sm" onClick={() => refetch()}>
                            Refresh
                        </Button>
                    </div>
                </div>

                <div className="p-6">
                    {isLoading ? (
                        <Loading />
                    ) : !activityData || activityData.length === 0 ? (
                        <div className="text-center py-8">
                            <ClockIcon className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                            <p className="text-gray-500 dark:text-gray-400">
                                No activity found for the selected filters.
                            </p>
                        </div>
                    ) : (
                        <div className="space-y-4">
                            {activityData.map((activity, index) => (
                                <div
                                    key={activity.id}
                                    className={`relative flex items-start space-x-4 p-4 border-l-4 rounded-r-lg ${getSeverityColor(activity.severity)}`}
                                >
                                    {/* Timeline line */}
                                    {index < activityData.length - 1 && (
                                        <div className="absolute left-6 top-12 w-0.5 h-8 bg-gray-200 dark:bg-gray-600" />
                                    )}

                                    {/* Activity icon */}
                                    <div className="flex-shrink-0 mt-1">
                                        {getActivityIcon(activity)}
                                    </div>

                                    {/* Activity content */}
                                    <div className="flex-1 min-w-0">
                                        <div className="flex items-start justify-between">
                                            <div className="flex-1">
                                                <div className="flex items-center space-x-2">
                                                    <p className="text-sm font-medium text-gray-900 dark:text-white">
                                                        {activity.actor}
                                                    </p>
                                                    {getSeverityIcon(activity.severity)}
                                                    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${activity.category === 'security'
                                                            ? 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'
                                                            : activity.category === 'sharing'
                                                                ? 'bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200'
                                                                : 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200'
                                                        }`}>
                                                        {activity.category}
                                                    </span>
                                                </div>
                                                <p className="text-sm text-gray-600 dark:text-gray-300 mt-1">
                                                    {getActivityDescription(activity)}
                                                </p>

                                                {/* Metadata */}
                                                {activity.metadata && (
                                                    <div className="mt-2 text-xs text-gray-500 dark:text-gray-400 space-y-1">
                                                        {activity.ipAddress && (
                                                            <div>IP: {activity.ipAddress}</div>
                                                        )}
                                                        {activity.metadata.namespace && (
                                                            <div>Namespace: {activity.metadata.namespace}</div>
                                                        )}
                                                        {activity.metadata.duration && (
                                                            <div>Duration: {activity.metadata.duration}</div>
                                                        )}
                                                    </div>
                                                )}
                                            </div>

                                            <div className="flex-shrink-0 text-right">
                                                <div className="text-xs text-gray-500 dark:text-gray-400">
                                                    {getFormattedDate(activity.timestamp)}
                                                </div>
                                                <div className="text-xs text-gray-500 dark:text-gray-400">
                                                    {getFormattedTime(activity.timestamp)}
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};