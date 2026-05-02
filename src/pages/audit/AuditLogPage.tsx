import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { ClockIcon } from '@heroicons/react/24/outline';
import { apiService } from '../../services/api';
import { Loading } from '../../components/ui/Loading';
import { Alert } from '../../components/ui/Alert';

const EVENT_TYPE_LABELS: Record<string, string> = {
    'secret.read':    'Read',
    'secret.created': 'Created',
    'secret.updated': 'Updated',
    'secret.deleted': 'Deleted',
    'auth.login':     'Login',
    // already-mapped values from the backend
    'accessed':       'Read',
    'created':        'Created',
    'updated':        'Updated',
    'deleted':        'Deleted',
};

function friendlyType(type: string): string {
    return EVENT_TYPE_LABELS[type] ?? type;
}

function formatTimestamp(ts: string | number | Date): string {
    const d = new Date(ts as string);
    if (isNaN(d.getTime())) return String(ts);
    return d.toLocaleString();
}

export const AuditLogPage: React.FC = () => {
    const { data, isLoading, error } = useQuery({
        queryKey: ['audit-log'],
        queryFn: () => apiService.dashboard.getActivity({ pageSize: 50 }),
    });

    return (
        <div className="p-6 space-y-6">
            <div>
                <h1 className="text-2xl font-semibold text-gray-900 dark:text-white">
                    Audit Log
                </h1>
                <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                    Complete record of all secret access and changes
                </p>
            </div>

            {error && (
                <Alert
                    type="error"
                    title="Failed to load audit log"
                    message="There was an error loading the audit log. Please try again."
                />
            )}

            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
                {isLoading ? (
                    <div className="p-8">
                        <Loading />
                    </div>
                ) : !data?.items?.length ? (
                    <div className="p-8 text-center">
                        <ClockIcon className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                        <p className="text-gray-500 dark:text-gray-400">
                            No activity recorded yet.
                        </p>
                    </div>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                            <thead className="bg-gray-50 dark:bg-gray-900">
                                <tr>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                                        Time
                                    </th>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                                        Event Type
                                    </th>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                                        User
                                    </th>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                                        Secret
                                    </th>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                                        Description
                                    </th>
                                </tr>
                            </thead>
                            <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                                {data.items.map((item) => (
                                    <tr key={item.id} className="hover:bg-gray-50 dark:hover:bg-gray-700">
                                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                                            {formatTimestamp(item.timestamp)}
                                        </td>
                                        <td className="px-6 py-4 whitespace-nowrap">
                                            <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200">
                                                {friendlyType(item.type)}
                                            </span>
                                        </td>
                                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white">
                                            {item.actor}
                                        </td>
                                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white">
                                            {item.secretName}
                                        </td>
                                        <td className="px-6 py-4 text-sm text-gray-500 dark:text-gray-400">
                                            {item.actor} {friendlyType(item.type).toLowerCase()} secret &quot;{item.secretName}&quot;
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>
        </div>
    );
};
