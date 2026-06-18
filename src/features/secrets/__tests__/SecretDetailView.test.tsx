import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '../../../test/test-utils';
import { SecretDetailView } from '../SecretDetailView';
import { Secret } from '../../../types';

const mockClassifyMutate = vi.fn();
const mockRollbackMutate = vi.fn();
let mockVersions: { EncryptedValue: string; VersionNumber: number; CreatedAt: string }[] = [];

vi.mock('../api', () => ({
    useSecretVersions: () => ({ data: mockVersions, isLoading: false, error: null }),
    useRotateSecret: () => ({ mutate: vi.fn(), reset: vi.fn(), isPending: false, isError: false }),
    useRollbackSecret: () => ({ mutate: mockRollbackMutate, isPending: false, isError: false }),
    useTransferOwnership: () => ({ mutate: vi.fn(), reset: vi.fn(), isPending: false, isError: false }),
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
        mockVersions = [];
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


describe('SecretDetailView version rollback', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        mockVersions = [
            { VersionNumber: 1, EncryptedValue: btoa('v1'), CreatedAt: '2026-06-10T00:00:00Z' },
            { VersionNumber: 2, EncryptedValue: btoa('v2'), CreatedAt: '2026-06-14T00:00:00Z' },
        ];
    });

    it('lists versions and rolls back a non-current one', () => {
        const confirmSpy = vi.spyOn(window, 'confirm').mockReturnValue(true);
        render(<SecretDetailView secret={makeSecret()} />);
        expect(screen.getByText('Version History')).toBeInTheDocument();
        // The current (highest) version has no rollback button; v1 does.
        const rollbackBtns = screen.getAllByRole('button', { name: /Roll back/i });
        expect(rollbackBtns).toHaveLength(1);
        fireEvent.click(rollbackBtns[0]);
        expect(mockRollbackMutate).toHaveBeenCalledWith(1, expect.anything());
        confirmSpy.mockRestore();
    });

    it('does not roll back when the confirm is declined', () => {
        const confirmSpy = vi.spyOn(window, 'confirm').mockReturnValue(false);
        render(<SecretDetailView secret={makeSecret()} />);
        fireEvent.click(screen.getByRole('button', { name: /Roll back/i }));
        expect(mockRollbackMutate).not.toHaveBeenCalled();
        confirmSpy.mockRestore();
    });
});
