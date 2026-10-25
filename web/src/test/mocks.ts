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

// Mock user data
export const mockUser: MockUser = {
    id: 1,
    username: 'testuser',
    email: 'test@example.com',
    role: 'user',
    permissions: ['secrets:read', 'secrets:write', 'shares:read', 'shares:write'],
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
        configurable: true,
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
