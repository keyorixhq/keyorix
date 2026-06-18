import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '../../../test/test-utils';
import { SecretDetailView } from '../SecretDetailView';
import { Secret } from '../../../types';

const mockClassifyMutate = vi.fn();
const mockRollbackMutate = vi.fn();
const mockSuspendMutate = vi.fn();
const mockResumeMutate = vi.fn();
let mockVersions: { EncryptedValue: string; VersionNumber: number; CreatedAt: string }[] = [];
let mockAccessors: { user_id: number; username: string; permission: string; source: string }[] = [];
let mockAccessLog: { AccessedBy: string; AccessTime: string; Action: string; IPAddress: string }[] = [];

vi.mock('../api', () => ({
    useSecretVersions: () => ({ data: mockVersions, isLoading: false, error: null }),
    useRotateSecret: () => ({ mutate: vi.fn(), reset: vi.fn(), isPending: false, isError: false }),
    useRollbackSecret: () => ({ mutate: mockRollbackMutate, isPending: false, isError: false }),
    useTransferOwnership: () => ({ mutate: vi.fn(), reset: vi.fn(), isPending: false, isError: false }),
    useSuspendSecret: () => ({ mutate: mockSuspendMutate, isPending: false }),
    useResumeSecret: () => ({ mutate: mockResumeMutate, isPending: false }),
    useSecretAccessors: () => ({ data: mockAccessors }),
    useSecretAccessLog: () => ({ data: mockAccessLog }),
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
        mockAccessors = [];
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

describe('SecretDetailView access list', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        mockVersions = [];
        mockAccessors = [
            { user_id: 1, username: 'owner', permission: 'owner', source: 'owner' },
            { user_id: 2, username: 'alice', permission: 'write', source: 'direct_share' },
            { user_id: 3, username: 'bob', permission: 'read', source: 'group_share:platform' },
        ];
    });

    it('renders the effective access list with permissions and sources', () => {
        render(<SecretDetailView secret={makeSecret()} />);
        expect(screen.getByText('Who can access')).toBeInTheDocument();
        expect(screen.getByText('bob')).toBeInTheDocument(); // unique to the access list
        expect(screen.getByText('group_share:platform')).toBeInTheDocument();
    });

    it('omits the section when there are no accessors', () => {
        mockAccessors = [];
        render(<SecretDetailView secret={makeSecret()} />);
        expect(screen.queryByText('Who can access')).not.toBeInTheDocument();
    });
});

describe('SecretDetailView suspend/resume', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        mockVersions = [];
        mockAccessors = [];
    });

    it('shows Suspend for an active secret and calls suspend on confirm', () => {
        const confirmSpy = vi.spyOn(window, 'confirm').mockReturnValue(true);
        render(<SecretDetailView secret={makeSecret({ status: 'active' })} />);
        expect(screen.queryByTestId('suspended-badge')).not.toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: /^Suspend$/i }));
        expect(mockSuspendMutate).toHaveBeenCalled();
        confirmSpy.mockRestore();
    });

    it('shows a Suspended badge and a Resume action for a suspended secret', () => {
        render(<SecretDetailView secret={makeSecret({ status: 'suspended' })} />);
        expect(screen.getByTestId('suspended-badge')).toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: /^Resume$/i }));
        expect(mockResumeMutate).toHaveBeenCalled();
    });
});

describe('SecretDetailView recent access', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        mockVersions = [];
        mockAccessors = [];
        mockAccessLog = [
            { AccessedBy: 'alice', AccessTime: '2026-06-18T10:00:00Z', Action: 'read', IPAddress: '10.0.0.7' },
        ];
    });

    it('renders the recent-access panel with accessor + ip', () => {
        render(<SecretDetailView secret={makeSecret()} />);
        expect(screen.getByText('Recent access')).toBeInTheDocument();
        expect(screen.getByText(/10\.0\.0\.7/)).toBeInTheDocument();
    });

    it('omits the panel when there is no access log', () => {
        mockAccessLog = [];
        render(<SecretDetailView secret={makeSecret()} />);
        expect(screen.queryByText('Recent access')).not.toBeInTheDocument();
    });
});
