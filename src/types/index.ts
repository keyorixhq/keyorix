// Core application types
export interface User {
    id: number;
    username: string;
    email: string;
    role: string;
    permissions: string[];
    preferences: UserPreferences;
    lastLogin: string;
}

export interface UserPreferences {
    language: string;
    timezone: string;
    theme: 'light' | 'dark' | 'system';
    notifications: NotificationSettings;
}

export interface NotificationSettings {
    email: boolean;
    browser: boolean;
    sharing: boolean;
    security: boolean;
}

// Secret management types
export interface Secret {
    id: number;
    name: string;
    type: SecretType;
    namespace: string;
    zone: string;
    environment: string;
    isShared: boolean;
    shareCount: number;
    lastModified: string;
    owner: string;
    permissions: string[];
    metadata: Record<string, string>;
    tags: string[];
}

export type SecretType = 'text' | 'password' | 'api_key' | 'certificate' | 'json';

export interface SecretFormData {
    name: string;
    value: string;
    type: SecretType;
    namespace: string;
    zone: string;
    environment: string;
    metadata: Record<string, string>;
    tags: string[];
}

// Sharing types
export interface ShareRecord {
    id: number;
    secretId: number;
    recipientType: 'user' | 'group';
    recipientId: number;
    recipientName: string;
    permission: 'read' | 'write';
    createdAt: string;
    createdBy: string;
}

export interface ShareFormData {
    recipientType: 'user' | 'group';
    recipientId: number;
    permission: 'read' | 'write';
}

export interface Recipient {
    id: number;
    name: string;
    type: 'user' | 'group';
    email?: string;
    memberCount?: number;
}

// Dashboard types
export interface StatTrend {
    value: number;
    isPositive: boolean;
}

export interface ExpiringSecret {
    id: number;
    name: string;
    environment: string;
    expiresAt: string;
    daysLeft: number;
}

export interface AnomalyAlert {
  ID: number;
  SecretName: string;
  AlertType: string;
  Severity: string;
  Description: string;
  AccessedBy: string;
  IPAddress: string;
  DetectedAt: string;
  Acknowledged: boolean;
}

export interface DashboardStats {
    totalSecrets: number;
    sharedSecrets: number;
    secretsSharedWithMe: number;
    recentActivity: ActivityItem[];
    totalSecretsTrend?: StatTrend;
    sharedSecretsTrend?: StatTrend;
    sharedWithMeTrend?: StatTrend;
    expiringSecrets?: ExpiringSecret[];
}

export interface ActivityItem {
    id: number;
    type: 'created' | 'updated' | 'shared' | 'accessed';
    secretName: string;
    timestamp: string;
    actor: string;
}

// Navigation types
export interface NavigationItem {
    name: string;
    href: string;
    icon: React.ComponentType;
    current: boolean;
    badge?: number;
}

// API types
export interface ApiResponse<T> {
    data: T;
    message: string;
    success: boolean;
}

export interface PaginatedResponse<T> {
    data: T[];
    total: number;
    page: number;
    pageSize: number;
    totalPages: number;
}

export interface ApiError {
    error: string;
    code: string;
    details?: Record<string, string>;
}

// Form types
export interface ValidationError {
    field: string;
    message: string;
}

// UI types
export interface AppNotification {
    id: string;
    type: 'success' | 'error' | 'warning' | 'info';
    title: string;
    message: string;
    timestamp: string;
    read: boolean;
}

// Filter and pagination types
export interface SecretFilters {
    search: string;
    type: SecretType | 'all';
    namespace: string;
    zone: string;
    environment: string;
    tags: string[];
}

export interface PaginationState {
    page: number;
    pageSize: number;
    total: number;
    totalPages: number;
}

// Authentication types
export interface LoginFormData {
    username: string;
    password: string;
    rememberMe: boolean;
}

export interface AuthState {
    user: User | null;
    token: string | null;
    isAuthenticated: boolean;
    isLoading: boolean;
    error: string | null;
}

export interface LoginResponse {
    token: string;
    expires_at: string;
    user_id: number;
    username: string;
    email: string;
}

export interface RefreshTokenResponse {
    token: string;
    expiresAt: string;
}

export interface PasswordResetRequest {
    email: string;
}

export interface PasswordResetConfirm {
    token: string;
    newPassword: string;
    confirmPassword: string;
}

// Environment types
export interface EnvironmentConfig {
    API_BASE_URL: string;
    API_TIMEOUT: number;
    APP_NAME: string;
    APP_VERSION: string;
    APP_DESCRIPTION: string;
    ENVIRONMENT: 'development' | 'staging' | 'production';
    ENABLE_DEBUG: boolean;
    ENABLE_DEVTOOLS: boolean;
    SESSION_TIMEOUT: number;
    CLIPBOARD_CLEAR_TIMEOUT: number;
    DEFAULT_LANGUAGE: string;
    DEFAULT_THEME: 'light' | 'dark' | 'system';
    ITEMS_PER_PAGE: number;
}