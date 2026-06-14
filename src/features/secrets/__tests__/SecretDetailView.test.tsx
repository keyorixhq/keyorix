import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '../../../test/test-utils';
import { SecretDetailView } from '../SecretDetailView';
import { Secret } from '../../../types';

const mockClassifyMutate = vi.fn();

vi.mock('../api', () => ({
    useSecretVersions: () => ({ data: [], isLoading: false, error: null }),
    useRotateSecret: () => ({ mutate: vi.fn(), reset: vi.fn(), isPending: false, isError: false }),
    useSecretRisk: () => ({ data: null }),
    useClassifySecret: () => ({ mutate: mockClassifyMutate, isPending: false }),
}));

const makeSecret = (overrides: Partial<Secret> = {}): Secret => ({
    id: 1,
    name: 'db-password',
    type: 'password',
    environment: 'production',
    isShared: false,
    shareCount: 0,
    lastModified: '2026-06-14T00:00:00Z',
    owner: 'alice',
    permissions: [],
    metadata: {},
    tags: [],
    classification: 'confidential',
    ...overrides,
});

describe('SecretDetailView classification', () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    it('shows the current classification level as a badge', () => {
        render(<SecretDetailView secret={makeSecret()} />);
        expect(screen.getByTestId('classification-badge')).toHaveTextContent('Confidential');
    });

    it('renders Unclassified when the secret has no classification', () => {
        render(<SecretDetailView secret={makeSecret({ classification: '' })} />);
        expect(screen.getByTestId('classification-badge')).toHaveTextContent('Unclassified');
    });

    it('calls the classify mutation when a new level is selected', () => {
        render(<SecretDetailView secret={makeSecret()} />);
        fireEvent.change(screen.getByLabelText('Classification'), { target: { value: 'restricted' } });
        expect(mockClassifyMutate).toHaveBeenCalledTimes(1);
        expect(mockClassifyMutate.mock.calls[0][0]).toBe('restricted');
    });

    it('updates the badge to the newly selected level', () => {
        render(<SecretDetailView secret={makeSecret({ classification: 'public' })} />);
        expect(screen.getByTestId('classification-badge')).toHaveTextContent('Public');
        fireEvent.change(screen.getByLabelText('Classification'), { target: { value: 'restricted' } });
        expect(screen.getByTestId('classification-badge')).toHaveTextContent('Restricted');
    });
});
