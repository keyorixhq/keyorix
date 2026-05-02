import React from 'react';
import { useQuery } from '@tanstack/react-query';
import {
    CheckCircleIcon,
    ExclamationTriangleIcon,
    XCircleIcon,
    ClockIcon,
    ServerIcon,
    CpuChipIcon,
    CircleStackIcon,
    GlobeAltIcon,
    ShieldCheckIcon,
    BoltIcon
} from '@heroicons/react/24/outline';
import { Loading } from '../ui/Loading';
import { Alert } from '../ui/Alert';
import { Button } from '../ui/Button';

interface SystemMetric {
    name: string;
    value: string | number;
    status: 'healthy' | 'warning' | 'critical';
    threshold?: {
        warning: number;
        critical: number;
    };
    unit?: string;
    description?: string;
}

interface ServiceStatus {
    name: string;
    status: 'online' | 'offline' | 'degraded';
    uptime: string;
    responseTime: number;
    lastCheck: string;
    endpoint?: string;
}

interface SystemHealthData {
    overall: 'healthy' | 'warning' | 'critical';
    metrics: SystemMetric[];
    services: ServiceStatus[];
    incidents: {
        id: string;
        title: string;
        status: 'investigating' | 'identified' | 'monitoring' | 'resolved';
        severity: 'low' | 'medium' | 'high' | 'critical';
        startTime: string;
        description: string;
    }[];
}

const StatusIndicator: React.FC<{ status: 'healthy' | 'warning' | 'critical' | 'online' | 'offline' | 'degraded' }> = ({ status }) => {
    const getStatusConfig = () => {
        switch (status) {
            case 'healthy':
            case 'online':
                return {
                    icon: CheckCircleIcon,
                    color: 'text-green-500',
                    bgColor: 'bg-green-100 dark:bg-green-900/20',
                    label: status === 'healthy' ? 'Healthy' : 'Online'
                };
            case 'warning':
            case 'degraded':
                return {
                    icon: ExclamationTriangleIcon,
                    color: 'text-yellow-500',
                    bgColor: 'bg-yellow-100 dark:bg-yellow-900/20',
                    label: status === 'warning' ? 'Warning' : 'Degraded'
                };
            case 'critical':
            case 'offline':
                return {
                    icon: XCircleIcon,
                    color: 'text-red-500',
                    bgColor: 'bg-red-100 dark:bg-red-900/20',
                    label: status === 'critical' ? 'Critical' : 'Offline'
                };
            default:
                return {
                    icon: ClockIcon,
                    color: 'text-gray-500',
                    bgColor: 'bg-gray-100 dark:bg-gray-700',
                    label: 'Unknown'
                };
        }
    };

    const config = getStatusConfig();
    const Icon = config.icon;

    return (
        <div className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${config.bgColor} ${config.color}`}>
            <Icon className="h-3 w-3 mr-1" />
            {config.label}
        </div>
    );
};

const MetricCard: React.FC<{ metric: SystemMetric }> = ({ metric }) => {
    const getMetricIcon = (name: string) => {
        const iconClass = "h-6 w-6";

        if (name.toLowerCase().includes('cpu')) {
            return <CpuChipIcon className={iconClass} />;
        } else if (name.toLowerCase().includes('memory') || name.toLowerCase().includes('ram')) {
            return <CircleStackIcon className={iconClass} />;
        } else if (name.toLowerCase().includes('disk') || name.toLowerCase().includes('storage')) {
            return <ServerIcon className={iconClass} />;
        } else if (name.toLowerCase().includes('network') || name.toLowerCase().includes('bandwidth')) {
            return <GlobeAltIcon className={iconClass} />;
        } else if (name.toLowerCase().includes('security')) {
            return <ShieldCheckIcon className={iconClass} />;
        } else {
            return <BoltIcon className={iconClass} />;
        }
    };

    const formatValue = (value: string | number, unit?: string) => {
        if (typeof value === 'number') {
            return `${value.toFixed(1)}${unit || ''}`;
        }
        return value;
    };

    return (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
            <div className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                    <div className="p-2 rounded-lg bg-blue-50 text-blue-600 dark:bg-blue-900/20 dark:text-blue-400">
                        {getMetricIcon(metric.name)}
                    </div>
                    <div>
                        <h3 className="text-sm font-medium text-gray-900 dark:text-white">
                            {metric.name}
                        </h3>
                        {metric.description && (
                            <p className="text-xs text-gray-500 dark:text-gray-400">
                                {metric.description}
                            </p>
                        )}
                    </div>
                </div>
                <div className="text-right">
                    <div className="text-lg font-semibold text-gray-900 dark:text-white">
                        {formatValue(metric.value, metric.unit)}
                    </div>
                    <StatusIndicator status={metric.status} />
                </div>
            </div>
        </div>
    );
};

const ServiceCard: React.FC<{ service: ServiceStatus }> = ({ service }) => {
    return (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
            <div className="flex items-center justify-between mb-3">
                <h3 className="text-sm font-medium text-gray-900 dark:text-white">
                    {service.name}
                </h3>
                <StatusIndicator status={service.status} />
            </div>

            <div className="space-y-2 text-xs text-gray-500 dark:text-gray-400">
                <div className="flex justify-between">
                    <span>Uptime:</span>
                    <span className="font-medium">{service.uptime}</span>
                </div>
                <div className="flex justify-between">
                    <span>Response Time:</span>
                    <span className="font-medium">{service.responseTime}ms</span>
                </div>
                <div className="flex justify-between">
                    <span>Last Check:</span>
                    <span className="font-medium">
                        {new Date(service.lastCheck).toLocaleTimeString()}
                    </span>
                </div>
                {service.endpoint && (
                    <div className="flex justify-between">
                        <span>Endpoint:</span>
                        <span className="font-medium font-mono text-xs truncate max-w-32">
                            {service.endpoint}
                        </span>
                    </div>
                )}
            </div>
        </div>
    );
};

export const SystemHealthMonitor: React.FC = () => {
    // Fetch system health data
    const { data: healthData, isLoading, error, refetch } = useQuery({
        queryKey: ['system', 'health'],
        queryFn: async (): Promise<SystemHealthData> => {
            // Mock system health data - in real app this would come from the API
            await new Promise(resolve => setTimeout(resolve, 1000));

            return {
                overall: 'healthy',
                metrics: [
                    {
                        name: 'CPU Usage',
                        value: 23.5,
                        unit: '%',
                        status: 'healthy',
                        threshold: { warning: 70, critical: 90 },
                        description: 'Average CPU utilization across all nodes'
                    },
                    {
                        name: 'Memory Usage',
                        value: 67.2,
                        unit: '%',
                        status: 'warning',
                        threshold: { warning: 80, critical: 95 },
                        description: 'Memory utilization across all services'
                    },
                    {
                        name: 'Disk Usage',
                        value: 45.8,
                        unit: '%',
                        status: 'healthy',
                        threshold: { warning: 80, critical: 95 },
                        description: 'Storage utilization'
                    },
                    {
                        name: 'Network I/O',
                        value: 125.3,
                        unit: 'MB/s',
                        status: 'healthy',
                        description: 'Network throughput'
                    },
                    {
                        name: 'Active Connections',
                        value: 1247,
                        status: 'healthy',
                        description: 'Current active database connections'
                    },
                    {
                        name: 'Response Time',
                        value: 45,
                        unit: 'ms',
                        status: 'healthy',
                        threshold: { warning: 200, critical: 500 },
                        description: 'Average API response time'
                    },
                ],
                services: [
                    {
                        name: 'API Server',
                        status: 'online',
                        uptime: '99.98%',
                        responseTime: 42,
                        lastCheck: new Date().toISOString(),
                        endpoint: '/api/health'
                    },
                    {
                        name: 'Database',
                        status: 'online',
                        uptime: '99.95%',
                        responseTime: 15,
                        lastCheck: new Date().toISOString(),
                        endpoint: 'postgresql://...'
                    },
                    {
                        name: 'Redis Cache',
                        status: 'online',
                        uptime: '99.99%',
                        responseTime: 2,
                        lastCheck: new Date().toISOString(),
                        endpoint: 'redis://...'
                    },
                    {
                        name: 'Authentication Service',
                        status: 'degraded',
                        uptime: '98.45%',
                        responseTime: 156,
                        lastCheck: new Date().toISOString(),
                        endpoint: '/auth/health'
                    },
                    {
                        name: 'File Storage',
                        status: 'online',
                        uptime: '99.87%',
                        responseTime: 89,
                        lastCheck: new Date().toISOString(),
                        endpoint: 's3://...'
                    },
                    {
                        name: 'Email Service',
                        status: 'online',
                        uptime: '99.92%',
                        responseTime: 234,
                        lastCheck: new Date().toISOString(),
                        endpoint: 'smtp://...'
                    },
                ],
                incidents: [
                    {
                        id: '1',
                        title: 'Elevated Authentication Response Times',
                        status: 'monitoring',
                        severity: 'medium',
                        startTime: new Date(Date.now() - 1000 * 60 * 45).toISOString(),
                        description: 'Authentication service experiencing higher than normal response times. Monitoring the situation.'
                    }
                ]
            };
        },
        refetchInterval: 30 * 1000, // Refetch every 30 seconds
        staleTime: 15 * 1000, // 15 seconds
    });

    const getOverallStatusConfig = (status: SystemHealthData['overall']) => {
        switch (status) {
            case 'healthy':
                return {
                    color: 'text-green-600 dark:text-green-400',
                    bgColor: 'bg-green-50 dark:bg-green-900/20',
                    borderColor: 'border-green-200 dark:border-green-800',
                    icon: CheckCircleIcon,
                    message: 'All systems operational'
                };
            case 'warning':
                return {
                    color: 'text-yellow-600 dark:text-yellow-400',
                    bgColor: 'bg-yellow-50 dark:bg-yellow-900/20',
                    borderColor: 'border-yellow-200 dark:border-yellow-800',
                    icon: ExclamationTriangleIcon,
                    message: 'Some systems experiencing issues'
                };
            case 'critical':
                return {
                    color: 'text-red-600 dark:text-red-400',
                    bgColor: 'bg-red-50 dark:bg-red-900/20',
                    borderColor: 'border-red-200 dark:border-red-800',
                    icon: XCircleIcon,
                    message: 'Critical system issues detected'
                };
            default:
                return {
                    color: 'text-gray-600 dark:text-gray-400',
                    bgColor: 'bg-gray-50 dark:bg-gray-700',
                    borderColor: 'border-gray-200 dark:border-gray-600',
                    icon: ClockIcon,
                    message: 'System status unknown'
                };
        }
    };

    if (error) {
        return (
            <Alert
                type="error"
                title="Failed to load system health"
                message="There was an error loading the system health data. Please try again."
                action={
                    <Button variant="outline" size="sm" onClick={() => refetch()}>
                        Retry
                    </Button>
                }
            />
        );
    }

    if (isLoading) {
        return <Loading />;
    }

    if (!healthData) {
        return null;
    }

    const statusConfig = getOverallStatusConfig(healthData.overall);
    const StatusIcon = statusConfig.icon;

    return (
        <div className="space-y-6">
            {/* Overall Status */}
            <div className={`rounded-lg border p-6 ${statusConfig.bgColor} ${statusConfig.borderColor}`}>
                <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                        <StatusIcon className={`h-8 w-8 ${statusConfig.color}`} />
                        <div>
                            <h2 className={`text-xl font-semibold ${statusConfig.color}`}>
                                System Status: {healthData.overall.charAt(0).toUpperCase() + healthData.overall.slice(1)}
                            </h2>
                            <p className={`text-sm ${statusConfig.color}`}>
                                {statusConfig.message}
                            </p>
                        </div>
                    </div>
                    <div className="text-right">
                        <div className="text-sm text-gray-500 dark:text-gray-400">
                            Last updated: {new Date().toLocaleTimeString()}
                        </div>
                        <Button variant="outline" size="sm" onClick={() => refetch()}>
                            Refresh
                        </Button>
                    </div>
                </div>
            </div>

            {/* Active Incidents */}
            {healthData.incidents.length > 0 && (
                <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
                    <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
                        <h3 className="text-lg font-medium text-gray-900 dark:text-white">
                            Active Incidents
                        </h3>
                    </div>
                    <div className="p-6 space-y-4">
                        {healthData.incidents.map((incident) => (
                            <div
                                key={incident.id}
                                className={`p-4 rounded-lg border ${incident.severity === 'critical'
                                        ? 'border-red-200 bg-red-50 dark:border-red-800 dark:bg-red-900/20'
                                        : incident.severity === 'high'
                                            ? 'border-orange-200 bg-orange-50 dark:border-orange-800 dark:bg-orange-900/20'
                                            : 'border-yellow-200 bg-yellow-50 dark:border-yellow-800 dark:bg-yellow-900/20'
                                    }`}
                            >
                                <div className="flex items-start justify-between">
                                    <div>
                                        <h4 className="font-medium text-gray-900 dark:text-white">
                                            {incident.title}
                                        </h4>
                                        <p className="text-sm text-gray-600 dark:text-gray-300 mt-1">
                                            {incident.description}
                                        </p>
                                        <div className="flex items-center space-x-4 mt-2 text-xs text-gray-500 dark:text-gray-400">
                                            <span>Started: {new Date(incident.startTime).toLocaleString()}</span>
                                            <span>Status: {incident.status}</span>
                                            <span>Severity: {incident.severity}</span>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* System Metrics */}
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
                <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
                    <h3 className="text-lg font-medium text-gray-900 dark:text-white">
                        System Metrics
                    </h3>
                </div>
                <div className="p-6">
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                        {healthData.metrics.map((metric, index) => (
                            <MetricCard key={index} metric={metric} />
                        ))}
                    </div>
                </div>
            </div>

            {/* Service Status */}
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
                <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
                    <h3 className="text-lg font-medium text-gray-900 dark:text-white">
                        Service Status
                    </h3>
                </div>
                <div className="p-6">
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                        {healthData.services.map((service, index) => (
                            <ServiceCard key={index} service={service} />
                        ))}
                    </div>
                </div>
            </div>
        </div>
    );
};