import { SecretType } from '../../types';

export const SECRET_TYPES: { value: SecretType | 'all'; label: string }[] = [
    { value: 'all', label: 'All Types' },
    { value: 'text', label: 'Text' },
    { value: 'password', label: 'Password' },
    { value: 'api_key', label: 'API Key' },
    { value: 'certificate', label: 'Certificate' },
    { value: 'json', label: 'JSON' },
];
