import React from 'react';
import { useQuery } from '@tanstack/react-query';
import {
    ClockIcon,
    UserIcon,
    UserGroupIcon,
    ShareIcon,
    PencilIcon,
    TrashIcon,
    EyeIcon,
    ShieldCheckIcon
} from '@heroicons/react/24/outline';
import { apiService } from '../../services/api';
import { usePreferencesStore } from '../../store/preferencesStore';
import { Secret, ShareRecord } from '../../types';
import { Loading } from '../ui/Loading';
import { Alert } from '../ui/Alert';

interface ShareHistoryViewProps {
    secret: Secret;
}

interface ShareActivity {
    id: string;
    type: 'created' | 'updated' | 'revoked' | 'accessed' | 'self_removed';
    timestamp: string;
    actor: string;
    recipientName: string;
    recipientType: 'user' | 'group';
    permission?: 'read' | 'write';
    previousPermission?: 'read' | 'write';
    details?: string;
}

export const ShareHistoryView: React.FC<ShareHistoryViewProps> = ({ secret }) => {
    const { getFormattedDate, getFormattedTime } = usePreferencesStore();

    // Fetch current shares
    const { data: shares, isLoading: sharesLoading } = useQuery({
        queryKey: ['sharing', 'by-secret', secret.id],
        queryFn: () => apiService.sharing.list({ secretId: secret.id }),
    });

    // Fetch audit logs (this would be a real API call in production)
    const { data: auditLogs, isLoading: auditLoading } = useQuery({
        queryKey: ['audit', 'sharing', secret.id],
        queryFn: async () => {
            // Mock audit data - in real app this would come from the API
            const mockAuditData: ShareActivity[] = [
                {
                    id: '1',
                    type: 'created',
                    timestamp: '2024-01-15T10:30:00Z',
                    actor: 'john.doe@company.com',
                    recipientName: 'Jane Smith',
                    recipientType: 'user',
                    permission: 'read',
                    details: 'Initial share created'
                },
                {
                    id: '2',
                    type: 'updated',
                    timestamp: '2024-01-16T14:20:00Z',
                    actor: 'john.doe@company.com',
                    recipientName: 'Jane Smith',
                    recipientType: 'user',
                    permission: 'write',
                    previousPermission: 'read',
                    details: 'Permission upgraded to read/write'
                },
                {
                    id: '3',
                    type: 'created',
                    timestamp: '2024-01-17T09:15:00Z',
                    actor: 'admin@company.com',
                    recipientName: 'DevOps Team',
                    recipientType: 'group',
                    permission: 'read',
                    details: 'Shared with team for deployment'
                },
                {
                    id: '4',
                    type: 'accessed',
                    timestamp: '2024-01-18T11:45:00Z',
                    actor: 'jane.smith@company.com',
                    recipientName: 'Jane Smith',
                    recipientType: 'user',
                    details: 'Secret value accessed'
                },
            ];

            // Simulate API delay
            await new Promise(resolve => setTimeout(resolve, 500));
            return mockAuditData;
        },
        staleTime: 2 * 60 * 1000, // 2 minutes
    });

    const getActivityIcon = (type: ShareActivity['type']) => {
        switch (type) {
            case 'created':
                return <ShareIcon className="h-5 w-5 text-green-500" />;
            case 'updated':
                return <PencilIcon className="h-5 w-5 text-blue-500" />;
            case 'revoked':
                return <TrashIcon className="h-5 w-5 text-red-500" />;
            case 'accessed':
                return <EyeIcon className="h-5 w-5 text-purple-500" />;
            case 'self_removed':
                return <ShieldCheckIcon className="h-5 w-5 text-orange-500" />;
            default:
                return <ClockIcon className="h-5 w-5 text-gray-500" />;
        }
    };

    const getActivityColor = (type: ShareActivity['type']) => {
        switch (type) {
            case 'created':
                return 'bg-green-50 border-green-200 dark:bg-green-900/20 dark:border-green-800';
            case 'updated':
                return 'bg-blue-50 border-blue-200 dark:bg-blue-900/20 dark:border-blue-800';
            case 'revoked':
                return 'bg-red-50 border-red-200 dark:bg-red-900/20 dark:border-red-800';
            case 'accessed':
                return 'bg-purple-50 border-purple-200 dark:bg-purple-900/20 dark:border-purple-800';
            case 'self_removed':
                return 'bg-orange-50 border-orange-200 dark:bg-orange-900/20 dark:border-orange-800';
            default:
                return 'bg-gray-50 border-gray-200 dark:bg-gray-700 dark:border-gray-600';
        }
    };

    const getActivityTitle = (activity: ShareActivity) => {
        switch (activity.type) {
            case 'created':
                return `Shared with ${activity.recipientName}`;
            case 'updated':
                return `Updated permissions for ${activity.recipientName}`;
            case 'revoked':
                return `Revoked access for ${activity.recipientName}`;
            case 'accessed':
                return `Secret accessed by ${activity.recipientName}`;
            case 'self_removed':
                return `${activity.recipientName} removed themselves`;
            default:
                return 'Unknown activity';
        }
    };

    const getActivityDescription = (activity: ShareActivity) => {
        switch (activity.type) {
            case 'created':
                return `${activity.permission === 'write' ? 'Read/Write' : 'Read-only'} access granted`;
            case 'updated':
                return `Permission changed from ${activity.previousPermission === 'write' ? 'Read/Write' : 'Read-only'} to ${activity.permission === 'write' ? 'Read/Write' : 'Read-only'}`;
            case 'revoked':
                return 'Access has been revoked';
            case 'accessed':
                return 'Secret value was viewed';
            case 'self_removed':
                return 'User removed their own access';
            default:
                return activity.details || '';
        }
    };

    if (sharesLoading || auditLoading) {
        return (
            <div className="p-6">
                <Loading />
            </div>
        );
    }

    return (
        <div className="space-y-6">
            {/* Current Shares */}
            <div>
                <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
                    Current Shares ({shares?.data.length || 0})
                </h3>

                {shares?.data.length === 0 ? (
                    <div className="text-center py-8">
                        <ShareIcon className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                        <p className="text-gray-500 dark:text-gray-400">
                            This secret is not currently shared with anyone.
                        </p>
                    </div>
                ) : (
                    <div className="space-y-3">
                        {shares?.data.map((share) => (
                            <div
                                key={share.id}
                                className="flex items-center justify-between p-4 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg"
                            >
                                <div className="flex items-center space-x-3">
                                    <div className="flex-shrink-0">
                                        {share.recipientType === 'user' ? (
                                            <UserIcon className="h-6 w-6 text-blue-500" />
                                        ) : (
                                            <UserGroupIcon className="h-6 w-6 text-green-500" />
                                        )}
                                    </div>
                                    <div>
                                        <div className="text-sm font-medium text-gray-900 dark:text-white">
                                            {share.recipientName}
                                        </div>
                                        <div className="text-xs text-gray-500 dark:text-gray-400 capitalize">
                                            {share.recipientType}
                                        </div>
                                    </div>
                                </div>

                                <div className="flex items-center space-x-3">
                                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${share.permission === 'write'
                                            ? 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'
                                            : 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200'
                                        }`}>
                                        {share.permission === 'write' ? 'Read & Write' : 'Read Only'}
                                    </span>

                                    <div className="text-xs text-gray-500 dark:text-gray-400">
                                        <div>by {share.createdBy}</div>
                                        <div>{getFormattedDate(share.createdAt)}</div>
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>
                )}
            </div>

            {/* Activity Timeline */}
            <div>
                <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
                    Sharing Activity
                </h3>

                {auditLogs?.length === 0 ? (
                    <div className="text-center py-8">
                        <ClockIcon className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                        <p className="text-gray-500 dark:text-gray-400">
                            No sharing activity recorded yet.
                        </p>
                    </div>
                ) : (
                    <div className="space-y-4">
                        {auditLogs?.map((activity, index) => (
                            <div
                                key={activity.id}
                                className={`relative flex items-start space-x-4 p-4 border rounded-lg ${getActivityColor(activity.type)}`}
                            >
                                {/* Timeline line */}
                                {index < (auditLogs.length - 1) && (
                                    <div className="absolute left-6 top-12 w-0.5 h-8 bg-gray-200 dark:bg-gray-600" />
                                )}

                                {/* Activity icon */}
                                <div className="flex-shrink-0 mt-1">
                                    {getActivityIcon(activity.type)}
                                </div>

                                {/* Activity content */}
                                <div className="flex-1 min-w-0">
                                    <div className="flex items-center justify-between">
                                        <div>
                                            <h4 className="text-sm font-medium text-gray-900 dark:text-white">
                                                {getActivityTitle(activity)}
                                            </h4>
                                            <p className="text-sm text-gray-600 dark:text-gray-300">
                                                {getActivityDescription(activity)}
                                            </p>
                                        </div>

                                        <div className="flex items-center space-x-2">
                                            {activity.recipientType === 'user' ? (
                                                <UserIcon className="h-4 w-4 text-gray-400" />
                                            ) : (
                                                <UserGroupIcon className="h-4 w-4 text-gray-400" />
                                            )}
                                        </div>
                                    </div>

                                    <div className="mt-2 flex items-center space-x-4 text-xs text-gray-500 dark:text-gray-400">
                                        <span>by {activity.actor}</span>
                                        <span>•</span>
                                        <span>{getFormattedDate(activity.timestamp)} at {getFormattedTime(activity.timestamp)}</span>
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>
                )}
            </div>

            {/* Security Notice */}
            <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4">
                <div className="flex items-start space-x-3">
                    <ShieldCheckIcon className="h-5 w-5 text-blue-600 dark:text-blue-400 mt-0.5" />
                    <div>
                        <h4 className="text-sm font-medium text-blue-900 dark:text-blue-100">
                            Security & Audit
                        </h4>
                        <p className="text-sm text-blue-700 dark:text-blue-200 mt-1">
                            All sharing activities are logged and monitored. Access to shared secrets is tracked
                            and can be audited at any time. Recipients can remove themselves from shares, and
                            owners can revoke access immediately.
                        </p>
                    </div>
                </div>
            </div>
        </div>
    );
};