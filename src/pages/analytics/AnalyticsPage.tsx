import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
    ChartBarIcon,
    ClockIcon,
    ArrowTrendingUpIcon,
    ArrowTrendingDownIcon,
    CalendarIcon,
    DocumentChartBarIcon,
    ArrowDownTrayIcon,
    FunnelIcon
} from '@heroicons/react/24/outline';
import { apiService } from '../../services/api';
import { queryKeys } from '../../lib/queryClient';
import { usePreferencesStore } from '../../store/preferencesStore';
import { Button } from '../../components/ui/Button';
import { Dropdown } from '../../components/ui/Dropdown';
import { Loading } from '../../components/ui/Loading';
import { Alert } from '../../components/ui/Alert';

interface AnalyticsMetric {
    label: string;
    value: number;
    change: number;
    changeType: 'increase' | 'decrease' | 'neutral';
    format: 'number' | 'percentage' | 'duration';
}

interface ChartData {
    labels: string[];
    datasets: {
        label: string;
        data: number[];
        color: string;
    }[];
}

const TIME_RANGES = [
    { value: '7d', label: 'Last 7 days' },
    { value: '30d', label: 'Last 30 days' },
    { value: '90d', label: 'Last 90 days' },
    { value: '1y', label: 'Last year' },
];

const METRIC_TYPES = [
    { value: 'all', label: 'All Metrics' },
    { value: 'secrets', label: 'Secret Management' },
    { value: 'sharing', label: 'Sharing Activity' },
    { value: 'access', label: 'Access Patterns' },
    { value: 'security', label: 'Security Events' },
];

const MetricCard: React.FC<{ metric: AnalyticsMetric }> = ({ metric }) => {
    const formatValue = (value: number, format: AnalyticsMetric['format']) => {
        switch (format) {
            case 'percentage':
                return `${value.toFixed(1)}%`;
            case 'duration':
                return `${value}ms`;
            default:
                return value.toLocaleString();
        }
    };

    const getChangeIcon = (changeType: AnalyticsMetric['changeType']) => {
        switch (changeType) {
            case 'increase':
                return <ArrowTrendingUpIcon className="h-4 w-4 text-green-500" />;
            case 'decrease':
                return <ArrowTrendingDownIcon className="h-4 w-4 text-red-500" />;
            default:
                return <div className="h-4 w-4" />;
        }
    };

    const getChangeColor = (changeType: AnalyticsMetric['changeType']) => {
        switch (changeType) {
            case 'increase':
                return 'text-green-600 dark:text-green-400';
            case 'decrease':
                return 'text-red-600 dark:text-red-400';
            default:
                return 'text-gray-600 dark:text-gray-400';
        }
    };

    return (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
            <div className="flex items-center justify-between">
                <div>
                    <p className="text-sm font-medium text-gray-600 dark:text-gray-400">
                        {metric.label}
                    </p>
                    <p className="text-3xl font-semibold text-gray-900 dark:text-white mt-2">
                        {formatValue(metric.value, metric.format)}
                    </p>
                    {metric.change !== 0 && (
                        <div className="flex items-center mt-2">
                            {getChangeIcon(metric.changeType)}
                            <span className={`text-sm font-medium ml-1 ${getChangeColor(metric.changeType)}`}>
                                {Math.abs(metric.change)}%
                            </span>
                            <span className="text-sm text-gray-500 dark:text-gray-400 ml-1">
                                vs previous period
                            </span>
                        </div>
                    )}
                </div>
                <div className="p-3 rounded-lg bg-blue-50 text-blue-600 dark:bg-blue-900/20 dark:text-blue-400">
                    <ChartBarIcon className="h-6 w-6" />
                </div>
            </div>
        </div>
    );
};

const SimpleChart: React.FC<{ data: ChartData; title: string; type: 'line' | 'bar' }> = ({
    data,
    title,
    type
}) => {
    // This is a simplified chart representation
    // In a real app, you'd use a library like Chart.js, Recharts, or D3
    const maxValue = Math.max(...data.datasets.flatMap(d => d.data));

    return (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
                {title}
            </h3>
            <div className="space-y-4">
                {data.datasets.map((dataset, datasetIndex) => (
                    <div key={datasetIndex}>
                        <div className="flex items-center mb-2">
                            <div
                                className="w-3 h-3 rounded-full mr-2"
                                style={{ backgroundColor: dataset.color }}
                            />
                            <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
                                {dataset.label}
                            </span>
                        </div>
                        <div className="grid grid-cols-7 gap-1 h-32">
                            {dataset.data.map((value, index) => (
                                <div key={index} className="flex flex-col justify-end">
                                    <div
                                        className="rounded-t"
                                        style={{
                                            backgroundColor: dataset.color,
                                            height: `${(value / maxValue) * 100}%`,
                                            minHeight: value > 0 ? '2px' : '0px'
                                        }}
                                    />
                                    <div className="text-xs text-gray-500 dark:text-gray-400 mt-1 text-center">
                                        {data.labels[index]}
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );
};

export const AnalyticsPage: React.FC = () => {
    const { getFormattedDate } = usePreferencesStore();
    const [timeRange, setTimeRange] = useState('30d');
    const [metricType, setMetricType] = useState('all');

    // Fetch analytics data
    const { data: analyticsData, isLoading, error } = useQuery({
        queryKey: ['analytics', timeRange, metricType],
        queryFn: async () => {
            // Mock analytics data - in real app this would come from the API
            await new Promise(resolve => setTimeout(resolve, 1000));

            return {
                metrics: [
                    {
                        label: 'Total Secrets',
                        value: 1247,
                        change: 12.5,
                        changeType: 'increase' as const,
                        format: 'number' as const,
                    },
                    {
                        label: 'Active Shares',
                        value: 342,
                        change: 8.3,
                        changeType: 'increase' as const,
                        format: 'number' as const,
                    },
                    {
                        label: 'Access Rate',
                        value: 94.2,
                        change: -2.1,
                        changeType: 'decrease' as const,
                        format: 'percentage' as const,
                    },
                    {
                        label: 'Avg Response Time',
                        value: 45,
                        change: -15.2,
                        changeType: 'increase' as const,
                        format: 'duration' as const,
                    },
                    {
                        label: 'Security Events',
                        value: 23,
                        change: -45.2,
                        changeType: 'decrease' as const,
                        format: 'number' as const,
                    },
                    {
                        label: 'User Adoption',
                        value: 87.5,
                        change: 5.7,
                        changeType: 'increase' as const,
                        format: 'percentage' as const,
                    },
                ] as AnalyticsMetric[],
                charts: {
                    secretsOverTime: {
                        labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
                        datasets: [
                            {
                                label: 'Secrets Created',
                                data: [12, 19, 8, 15, 22, 7, 14],
                                color: '#3B82F6',
                            },
                            {
                                label: 'Secrets Accessed',
                                data: [45, 52, 38, 61, 73, 29, 48],
                                color: '#10B981',
                            },
                        ],
                    },
                    sharingActivity: {
                        labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
                        datasets: [
                            {
                                label: 'New Shares',
                                data: [5, 8, 3, 7, 12, 2, 6],
                                color: '#8B5CF6',
                            },
                            {
                                label: 'Share Revocations',
                                data: [1, 2, 1, 0, 3, 0, 1],
                                color: '#EF4444',
                            },
                        ],
                    },
                    userActivity: {
                        labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
                        datasets: [
                            {
                                label: 'Active Users',
                                data: [89, 94, 87, 102, 115, 67, 78],
                                color: '#F59E0B',
                            },
                        ],
                    },
                },
            };
        },
        staleTime: 5 * 60 * 1000, // 5 minutes
    });

    const handleExportReport = () => {
        // In a real app, this would generate and download a report
        console.log('Exporting analytics report...');
    };

    if (error) {
        return (
            <div className="p-6">
                <Alert
                    type="error"
                    title="Failed to load analytics"
                    message="There was an error loading the analytics data. Please try again."
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
                        Analytics & Reporting
                    </h1>
                    <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                        Insights into your secret management usage and security
                    </p>
                </div>
                <div className="flex items-center space-x-3">
                    <Button
                        variant="outline"
                        onClick={handleExportReport}
                    >
                        <ArrowDownTrayIcon className="h-4 w-4 mr-2" />
                        Export Report
                    </Button>
                </div>
            </div>

            {/* Filters */}
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
                <div className="flex items-center space-x-4">
                    <div className="flex items-center space-x-2">
                        <CalendarIcon className="h-5 w-5 text-gray-400" />
                        <Dropdown
                            value={timeRange}
                            onChange={setTimeRange}
                            options={TIME_RANGES}
                            placeholder="Time Range"
                        />
                    </div>
                    <div className="flex items-center space-x-2">
                        <FunnelIcon className="h-5 w-5 text-gray-400" />
                        <Dropdown
                            value={metricType}
                            onChange={setMetricType}
                            options={METRIC_TYPES}
                            placeholder="Metric Type"
                        />
                    </div>
                    <div className="text-sm text-gray-500 dark:text-gray-400">
                        Last updated: {getFormattedDate(new Date().toISOString())}
                    </div>
                </div>
            </div>

            {/* Metrics Grid */}
            {isLoading ? (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                    {Array.from({ length: 6 }).map((_, i) => (
                        <div key={i} className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
                            <Loading />
                        </div>
                    ))}
                </div>
            ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                    {analyticsData?.metrics.map((metric, index) => (
                        <MetricCard key={index} metric={metric} />
                    ))}
                </div>
            )}

            {/* Charts */}
            {isLoading ? (
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    {Array.from({ length: 3 }).map((_, i) => (
                        <div key={i} className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
                            <Loading />
                        </div>
                    ))}
                </div>
            ) : (
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <SimpleChart
                        data={analyticsData?.charts.secretsOverTime!}
                        title="Secret Management Activity"
                        type="bar"
                    />
                    <SimpleChart
                        data={analyticsData?.charts.sharingActivity!}
                        title="Sharing Activity"
                        type="bar"
                    />
                    <div className="lg:col-span-2">
                        <SimpleChart
                            data={analyticsData?.charts.userActivity!}
                            title="User Activity Trends"
                            type="line"
                        />
                    </div>
                </div>
            )}

            {/* Detailed Reports */}
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
                <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
                    <h2 className="text-lg font-medium text-gray-900 dark:text-white">
                        Detailed Reports
                    </h2>
                </div>
                <div className="p-6">
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                        <Button
                            variant="outline"
                            className="flex items-center justify-center p-6 h-auto"
                        >
                            <div className="text-center">
                                <DocumentChartBarIcon className="h-8 w-8 text-blue-500 mx-auto mb-2" />
                                <div className="font-medium text-gray-900 dark:text-white">
                                    Security Report
                                </div>
                                <div className="text-sm text-gray-500 dark:text-gray-400">
                                    Comprehensive security analysis
                                </div>
                            </div>
                        </Button>

                        <Button
                            variant="outline"
                            className="flex items-center justify-center p-6 h-auto"
                        >
                            <div className="text-center">
                                <ChartBarIcon className="h-8 w-8 text-green-500 mx-auto mb-2" />
                                <div className="font-medium text-gray-900 dark:text-white">
                                    Usage Report
                                </div>
                                <div className="text-sm text-gray-500 dark:text-gray-400">
                                    Detailed usage statistics
                                </div>
                            </div>
                        </Button>

                        <Button
                            variant="outline"
                            className="flex items-center justify-center p-6 h-auto"
                        >
                            <div className="text-center">
                                <ClockIcon className="h-8 w-8 text-purple-500 mx-auto mb-2" />
                                <div className="font-medium text-gray-900 dark:text-white">
                                    Audit Report
                                </div>
                                <div className="text-sm text-gray-500 dark:text-gray-400">
                                    Complete audit trail
                                </div>
                            </div>
                        </Button>
                    </div>
                </div>
            </div>

            {/* Insights & Recommendations */}
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
                <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
                    <h2 className="text-lg font-medium text-gray-900 dark:text-white">
                        Insights & Recommendations
                    </h2>
                </div>
                <div className="p-6 space-y-4">
                    <div className="flex items-start space-x-3 p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
                        <ArrowTrendingUpIcon className="h-5 w-5 text-blue-500 mt-0.5" />
                        <div>
                            <h4 className="text-sm font-medium text-blue-900 dark:text-blue-100">
                                Increased Secret Creation
                            </h4>
                            <p className="text-sm text-blue-700 dark:text-blue-200 mt-1">
                                Secret creation has increased by 12.5% this month. Consider reviewing
                                your secret organization and naming conventions.
                            </p>
                        </div>
                    </div>

                    <div className="flex items-start space-x-3 p-4 bg-green-50 dark:bg-green-900/20 rounded-lg">
                        <ArrowTrendingUpIcon className="h-5 w-5 text-green-500 mt-0.5" />
                        <div>
                            <h4 className="text-sm font-medium text-green-900 dark:text-green-100">
                                Improved Sharing Adoption
                            </h4>
                            <p className="text-sm text-green-700 dark:text-green-200 mt-1">
                                Team collaboration through secret sharing has improved by 8.3%.
                                Great job on adopting secure sharing practices!
                            </p>
                        </div>
                    </div>

                    <div className="flex items-start space-x-3 p-4 bg-yellow-50 dark:bg-yellow-900/20 rounded-lg">
                        <ArrowTrendingDownIcon className="h-5 w-5 text-yellow-500 mt-0.5" />
                        <div>
                            <h4 className="text-sm font-medium text-yellow-900 dark:text-yellow-100">
                                Security Events Detected
                            </h4>
                            <p className="text-sm text-yellow-700 dark:text-yellow-200 mt-1">
                                23 security events were detected this period. Review the security
                                report for detailed analysis and recommended actions.
                            </p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};