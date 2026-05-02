import { vi } from 'vitest';

// Mock data types
export interface MockUser {
    id: number;
    username: string;
    email: string;
    role: string;
    permissions: string[];
}

export interface MockSecret {
    id: number;
    name: string;
    type: string;
    namespace: string;
    zone: string;
    environment: string;
    value: string;
    isShared: boolean;
    shareCount: number;
    lastModified: string;
    owner: string;
    permissions: string[];
    tags: string[];
    metadata: Record<string, string>;
}

export interface MockShare {
    id: number;
    secretId: number;
    recipientType: 'user' | 'group';
    recipientId: number;
    recipientName: string;
    permission: 'read' | 'write';
    createdAt: string;
    createdBy: string;
}

// Mock user data
export const mockUser: MockUser = {
    id: 1,
    username: 'testuser',
    email: 'test@example.com',
    role: 'user',
    permissions: ['secrets:read', 'secrets:write', 'shares:read', 'shares:write'],
};

export const mockAdminUser: MockUser = {
    id: 2,
    username: 'admin',
    email: 'admin@example.com',
    role: 'admin',
    permissions: [
        'secrets:read',
        'secrets:write',
        'secrets:delete',
        'shares:read',
        'shares:write',
        'shares:delete',
        'users:read',
        'users:write',
        'system:admin',
    ],
};

// Mock secret data
export const mockSecrets: MockSecret[] = [
    {
        id: 1,
        name: 'database-password',
        type: 'password',
        namespace: 'production',
        zone: 'us-east-1',
        environment: 'prod',
        value: 'super-secret-password',
        isShared: false,
        shareCount: 0,
        lastModified: '2024-01-15T10:30:00Z',
        owner: 'testuser',
        permissions: ['read', 'write'],
        tags: ['database', 'production'],
        metadata: {
            description: 'Production database password',
            rotation_schedule: '90d',
        },
    },
    {
        id: 2,
        name: 'api-key',
        type: 'api_key',
        namespace: 'development',
        zone: 'us-west-2',
        environment: 'dev',
        value: 'sk-1234567890abcdef',
        isShared: true,
        shareCount: 2,
        lastModified: '2024-01-14T15:45:00Z',
        owner: 'testuser',
        permissions: ['read'],
        tags: ['api', 'development'],
        metadata: {
            description: 'Development API key',
            service: 'payment-gateway',
        },
    },
    {
        id: 3,
        name: 'ssl-certificate',
        type: 'certificate',
        namespace: 'production',
        zone: 'eu-west-1',
        environment: 'prod',
        value: '-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----',
        isShared: false,
        shareCount: 0,
        lastModified: '2024-01-13T09:15:00Z',
        owner: 'admin',
        permissions: ['read'],
        tags: ['ssl', 'certificate', 'production'],
        metadata: {
            description: 'SSL certificate for production',
            expires: '2025-01-13',
        },
    },
];

// Mock share data
export const mockShares: MockShare[] = [
    {
        id: 1,
        secretId: 2,
        recipientType: 'user',
        recipientId: 3,
        recipientName: 'developer',
        permission: 'read',
        createdAt: '2024-01-14T16:00:00Z',
        createdBy: 'testuser',
    },
    {
        id: 2,
        secretId: 2,
        recipientType: 'group',
        recipientId: 1,
        recipientName: 'dev-team',
        permission: 'read',
        createdAt: '2024-01-14T16:05:00Z',
        createdBy: 'testuser',
    },
];

// API response mocks
export const mockApiResponse = <T>(data: T) => ({
    data,
    message: 'Success',
    success: true,
});

export const mockPaginatedResponse = <T>(data: T[], page = 1, pageSize = 10) => ({
    data,
    total: data.length,
    page,
    pageSize,
    totalPages: Math.ceil(data.length / pageSize),
});

export const mockApiError = (message: string, code = 'ERROR') => ({
    error: message,
    code,
    success: false,
});

// Mock API client
export const mockApiClient = {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
    patch: vi.fn(),
};

// Mock React Query hooks
export const mockUseQuery = vi.fn();
export const mockUseMutation = vi.fn();

// Mock router hooks
export const mockUseNavigate = vi.fn();
export const mockUseLocation = vi.fn(() => ({
    pathname: '/',
    search: '',
    hash: '',
    state: null,
}));
export const mockUseParams = vi.fn(() => ({}));

// Mock local storage
export const mockLocalStorage = {
    getItem: vi.fn(),
    setItem: vi.fn(),
    removeItem: vi.fn(),
    clear: vi.fn(),
};

// Mock clipboard API
export const mockClipboard = {
    writeText: vi.fn().mockResolvedValue(undefined),
    readText: vi.fn().mockResolvedValue(''),
};

// Setup function to apply common mocks
export const setupMocks = () => {
    // Mock localStorage
    Object.defineProperty(window, 'localStorage', {
        value: mockLocalStorage,
        writable: true,
    });

    // Mock clipboard
    Object.defineProperty(navigator, 'clipboard', {
        value: mockClipboard,
        writable: true,
    });

    // Mock scrollTo
    window.scrollTo = vi.fn() as unknown as typeof window.scrollTo;

    // Mock alert, confirm, prompt
    window.alert = vi.fn();
    window.confirm = vi.fn().mockReturnValue(true);
    window.prompt = vi.fn();

    // Reset all mocks
    vi.clearAllMocks();
};

// Cleanup function
export const cleanupMocks = () => {
    vi.clearAllMocks();
    vi.resetAllMocks();
};