import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';

// Mock translations for testing
const resources = {
    en: {
        translation: {
            // Common translations
            'common.loading': 'Loading...',
            'common.error': 'Error',
            'common.success': 'Success',
            'common.cancel': 'Cancel',
            'common.save': 'Save',
            'common.delete': 'Delete',
            'common.edit': 'Edit',
            'common.create': 'Create',
            'common.search': 'Search',
            'common.filter': 'Filter',
            'common.sort': 'Sort',
            'common.actions': 'Actions',
            'common.name': 'Name',
            'common.type': 'Type',
            'common.value': 'Value',
            'common.description': 'Description',
            'common.created': 'Created',
            'common.modified': 'Modified',
            'common.owner': 'Owner',

            // Auth translations
            'auth.login': 'Login',
            'auth.logout': 'Logout',
            'auth.email': 'Email',
            'auth.password': 'Password',
            'auth.remember_me': 'Remember me',
            'auth.forgot_password': 'Forgot password?',
            'auth.invalid_credentials': 'Invalid credentials',
            'auth.session_expired': 'Session expired',

            // Secret translations
            'secrets.title': 'Secrets',
            'secrets.create': 'Create Secret',
            'secrets.edit': 'Edit Secret',
            'secrets.delete': 'Delete Secret',
            'secrets.share': 'Share Secret',
            'secrets.no_secrets': 'No secrets found',
            'secrets.search_placeholder': 'Search secrets...',
            'secrets.namespace': 'Namespace',
            'secrets.zone': 'Zone',
            'secrets.environment': 'Environment',
            'secrets.tags': 'Tags',
            'secrets.metadata': 'Metadata',

            // Sharing translations
            'sharing.title': 'Sharing',
            'sharing.share_with': 'Share with',
            'sharing.permissions': 'Permissions',
            'sharing.read': 'Read',
            'sharing.write': 'Write',
            'sharing.shared_by': 'Shared by',
            'sharing.shared_with': 'Shared with',
            'sharing.revoke': 'Revoke',
            'sharing.self_remove': 'Remove myself',

            // Dashboard translations
            'dashboard.title': 'Dashboard',
            'dashboard.overview': 'Overview',
            'dashboard.recent_activity': 'Recent Activity',
            'dashboard.statistics': 'Statistics',
            'dashboard.total_secrets': 'Total Secrets',
            'dashboard.shared_secrets': 'Shared Secrets',
            'dashboard.secrets_shared_with_me': 'Secrets Shared With Me',

            // Profile translations
            'profile.title': 'Profile',
            'profile.settings': 'Settings',
            'profile.change_password': 'Change Password',
            'profile.language': 'Language',
            'profile.theme': 'Theme',
            'profile.timezone': 'Timezone',
            'profile.notifications': 'Notifications',

            // Error messages
            'errors.network': 'Network error occurred',
            'errors.unauthorized': 'Unauthorized access',
            'errors.forbidden': 'Access forbidden',
            'errors.not_found': 'Resource not found',
            'errors.server': 'Server error occurred',
            'errors.validation': 'Validation error',
            'errors.required_field': 'This field is required',
            'errors.invalid_email': 'Invalid email format',
            'errors.password_too_short': 'Password is too short',
        },
    },
};

i18n
    .use(initReactI18next)
    .init({
        resources,
        lng: 'en',
        fallbackLng: 'en',
        debug: false,
        interpolation: {
            escapeValue: false,
        },
        react: {
            useSuspense: false,
        },
    });

export default i18n;