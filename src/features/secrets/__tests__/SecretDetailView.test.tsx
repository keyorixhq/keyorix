import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '../../../test/test-utils';
import { SecretDetailView } from '../SecretDetailView';
import { Secret } from '../../../types';

const mockClassifyMutate = vi.fn();
const mockRollbackMutate = vi.fn();
const mockSuspendMutate = vi.fn();
const mockResumeMutate = vi.fn();
const mockRotateMutate = vi.fn();
const mockRotateReset = vi.fn();
const mockCopyMutate = vi.fn();
let mockVersions: { EncryptedValue: string; VersionNumber: number; CreatedAt: string }[] = [];
let mockVersionsLoading = false;
let mockVersionsError: unknown = null;
let mockAccessors: { user_id: number; username: string; permission: string; source: string }[] = [];
let mockAccessLog: { AccessedBy: string; AccessTime: string; Action: string; IPAddress: string }[] = [];
let mockAuditTrail: {
    id: number;
    event_type: string;
    timestamp: string;
    actor_type: string;
    description: string;
    success: boolean;
}[] = [];
let mockTags: string[] = [];
const setTagsMutate = vi.fn();
let mockDescription = '';
const setDescriptionMutate = vi.fn();
let mockDescriptionState: { isPending: boolean } = { isPending: false };
let mockRotateState: { isPending: boolean; isError: boolean } = { isPending: false, isError: false };
let mockRollbackState: { isPending: boolean; isError: boolean; error: unknown } = {
    isPending: false,
    isError: false,
    error: null,
};
let mockCopyState: { isPending: boolean } = { isPending: false };
let mockRisk: {
    score: number;
    band: 'low' | 'medium' | 'high';
    factors: { key: string; label: string; score: number; weight: number; detail: string }[];
} | null = null;
let mockCertificate: { data: any; isLoading: boolean; isError: boolean } = {
    data: undefined,
    isLoading: false,
    isError: true,
};

vi.mock('../api', () => ({
    useSecretVersions: () => ({ data: mockVersions, isLoading: mockVersionsLoading, error: mockVersionsError }),
    useRotateSecret: () => ({
        mutate: mockRotateMutate,
        reset: mockRotateReset,
        isPending: mockRotateState.isPending,
        isError: mockRotateState.isError,
    }),
    useRollbackSecret: () => ({
        mutate: mockRollbackMutate,
        isPending: mockRollbackState.isPending,
        isError: mockRollbackState.isError,
        error: mockRollbackState.error,
    }),
    useTransferOwnership: () => ({ mutate: vi.fn(), reset: vi.fn(), isPending: false, isError: false }),
    useSuspendSecret: () => ({ mutate: mockSuspendMutate, isPending: false }),
    useResumeSecret: () => ({ mutate: mockResumeMutate, isPending: false }),
    useSecretAccessors: () => ({ data: mockAccessors }),
    useSecretAccessLog: () => ({ data: mockAccessLog }),
    useSecretAuditTrail: () => ({ data: mockAuditTrail }),
    useSecretTags: () => ({ data: mockTags }),
    useSetSecretTags: () => ({ mutate: setTagsMutate, isPending: false }),
    useSecretDescription: () => ({ data: mockDescription }),
    useSetSecretDescription: () => ({ mutate: setDescriptionMutate, isPending: mockDescriptionState.isPending }),
    useCopySecret: () => ({ mutate: mockCopyMutate, isPending: mockCopyState.isPending }),
    useSecretRisk: () => ({ data: mockRisk }),
    useClassifySecret: () => ({ mutate: mockClassifyMutate, isPending: false }),
    // Secret dependency graph (ADR-052) — rendered by SecretDependenciesSection.
    useSecretDependencies: () => ({ data: { secret_id: 1, depends_on: [], dependents: [] } }),
    useSecretImpact: () => ({ data: { secret_id: 1, secret_name: 'db-password', affected: [] } }),
    useSecrets: () => ({ data: { data: [], total: 0, page: 1, pageSize: 20, totalPages: 1 } }),
    useAddSecretDependency: () => ({ mutate: vi.fn(), mutateAsync: vi.fn(), isPending: false }),
    useRemoveSecretDependency: () => ({ mutate: vi.fn(), isPending: false }),
    // Certificate panel (ADR-054) — only rendered for certificate-typed secrets.
    useSecretCertificate: () => mockCertificate,
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

    it('renders Unclassified when the secret classification is undefined (nullish fallback)', () => {
        render(<SecretDetailView secret={makeSecret({ classification: undefined })} />);
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

    it('does not call the mutation when re-selecting the current level', () => {
        render(<SecretDetailView secret={makeSecret({ classification: 'confidential' })} />);
        fireEvent.change(screen.getByLabelText('Classification'), { target: { value: 'confidential' } });
        expect(mockClassifyMutate).not.toHaveBeenCalled();
    });

    it('reverts the badge if the classify mutation fails', () => {
        mockClassifyMutate.mockImplementationOnce((_level: string, opts?: { onError?: () => void }) => {
            opts?.onError?.();
        });
        render(<SecretDetailView secret={makeSecret({ classification: 'confidential' })} />);
        fireEvent.change(screen.getByLabelText('Classification'), { target: { value: 'restricted' } });
        expect(screen.getByTestId('classification-badge')).toHaveTextContent('Confidential');
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

    it('does not suspend when the confirmation is declined', () => {
        const confirmSpy = vi.spyOn(window, 'confirm').mockReturnValue(false);
        render(<SecretDetailView secret={makeSecret({ status: 'active' })} />);
        fireEvent.click(screen.getByRole('button', { name: /^Suspend$/i }));
        expect(mockSuspendMutate).not.toHaveBeenCalled();
        confirmSpy.mockRestore();
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

    it('falls back to "unknown" for an empty accessor and omits the IP separator when absent', () => {
        mockAccessLog = [{ AccessedBy: '', AccessTime: '2026-06-18T10:00:00Z', Action: 'read', IPAddress: '' }];
        render(<SecretDetailView secret={makeSecret()} />);
        expect(screen.getByText('unknown')).toBeInTheDocument();
        expect(screen.getByText('read')).toBeInTheDocument();
    });

    it('shows relative times across the today/yesterday/days/months/years ranges', () => {
        const today = new Date(Date.now() - 60 * 1000).toISOString();
        const yesterday = new Date(Date.now() - 36 * 60 * 60 * 1000).toISOString();
        const fiveDaysAgo = new Date(Date.now() - (5 * 86_400_000 + 3_600_000)).toISOString();
        const threeMonthsAgo = new Date(Date.now() - (90 * 86_400_000 + 3_600_000)).toISOString();
        const oneYearAgo = new Date(Date.now() - (400 * 86_400_000 + 3_600_000)).toISOString();
        const twoYearsAgo = new Date(Date.now() - (800 * 86_400_000 + 3_600_000)).toISOString();
        mockAccessLog = [
            { AccessedBy: 'alice', AccessTime: today, Action: 'read', IPAddress: '' },
            { AccessedBy: 'bob', AccessTime: yesterday, Action: 'read', IPAddress: '' },
            { AccessedBy: 'carol', AccessTime: fiveDaysAgo, Action: 'read', IPAddress: '' },
            { AccessedBy: 'frank', AccessTime: threeMonthsAgo, Action: 'read', IPAddress: '' },
            { AccessedBy: 'dave', AccessTime: oneYearAgo, Action: 'read', IPAddress: '' },
            { AccessedBy: 'erin', AccessTime: twoYearsAgo, Action: 'read', IPAddress: '' },
        ];
        render(<SecretDetailView secret={makeSecret()} />);
        expect(screen.getByText('today')).toBeInTheDocument();
        expect(screen.getByText('yesterday')).toBeInTheDocument();
        expect(screen.getByText('5 days ago')).toBeInTheDocument();
        expect(screen.getByText('3 months ago')).toBeInTheDocument();
        expect(screen.getByText('1 year ago')).toBeInTheDocument();
        expect(screen.getByText('2 years ago')).toBeInTheDocument();
    });

    it('caps the list at 25 entries and shows a "showing" summary', () => {
        mockAccessLog = Array.from({ length: 26 }, (_, i) => ({
            AccessedBy: `user${i}`,
            AccessTime: new Date(Date.now() - i * 60_000).toISOString(),
            Action: 'read',
            IPAddress: '',
        }));
        render(<SecretDetailView secret={makeSecret()} />);
        expect(screen.getByText('Showing the 25 most recent of 26.')).toBeInTheDocument();
        expect(screen.queryByText('user25')).not.toBeInTheDocument();
    });
});

describe('SecretDetailView history', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        mockVersions = [];
        mockAccessors = [];
        mockAccessLog = [];
        mockAuditTrail = [
            {
                id: 2,
                event_type: 'secret.suspended',
                timestamp: '2026-06-18T12:00:00Z',
                actor_type: 'user',
                description: 'frozen for incident',
                success: true,
            },
            {
                id: 1,
                event_type: 'secret.created',
                timestamp: '2026-06-18T10:00:00Z',
                actor_type: 'user',
                description: '',
                success: true,
            },
        ];
    });

    it('renders the history panel with humanized event labels', () => {
        render(<SecretDetailView secret={makeSecret()} />);
        expect(screen.getByText('History')).toBeInTheDocument();
        expect(screen.getByText('Suspended')).toBeInTheDocument();
        expect(screen.getByText('Created')).toBeInTheDocument();
        expect(screen.getByText('frozen for incident')).toBeInTheDocument();
    });

    it('omits the panel when there is no audit trail', () => {
        mockAuditTrail = [];
        render(<SecretDetailView secret={makeSecret()} />);
        expect(screen.queryByText('History')).not.toBeInTheDocument();
    });

    it('shows a "machine" badge for machine-identity actors', () => {
        mockAuditTrail = [
            {
                id: 3,
                event_type: 'secret.rotated',
                timestamp: '2026-06-18T12:00:00Z',
                actor_type: 'machine_identity',
                description: '',
                success: true,
            },
        ];
        render(<SecretDetailView secret={makeSecret()} />);
        expect(screen.getByText('machine')).toBeInTheDocument();
    });

    it('falls back to a humanized raw event type for unknown events', () => {
        mockAuditTrail = [
            {
                id: 4,
                event_type: 'secret.custom_thing',
                timestamp: '2026-06-18T12:00:00Z',
                actor_type: 'user',
                description: '',
                success: true,
            },
        ];
        render(<SecretDetailView secret={makeSecret()} />);
        expect(screen.getByText('custom thing')).toBeInTheDocument();
    });
});

describe('SecretDetailView tags', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        mockVersions = [];
        mockAccessors = [];
        mockAccessLog = [];
        mockAuditTrail = [];
        mockTags = ['prod', 'tier1'];
        setTagsMutate.mockClear();
    });

    it('renders the tag chips', () => {
        render(<SecretDetailView secret={makeSecret()} />);
        expect(screen.getByText('Tags')).toBeInTheDocument();
        expect(screen.getByText('prod')).toBeInTheDocument();
        expect(screen.getByText('tier1')).toBeInTheDocument();
    });

    it('adds a tag on Enter', () => {
        render(<SecretDetailView secret={makeSecret()} />);
        const input = screen.getByPlaceholderText(/add a tag/i);
        fireEvent.change(input, { target: { value: 'web' } });
        fireEvent.keyDown(input, { key: 'Enter' });
        expect(setTagsMutate).toHaveBeenCalledTimes(1);
        expect(setTagsMutate.mock.calls[0][0]).toEqual(['prod', 'tier1', 'web']);
    });

    it('removes a tag', () => {
        render(<SecretDetailView secret={makeSecret()} />);
        fireEvent.click(screen.getByRole('button', { name: /remove tag prod/i }));
        expect(setTagsMutate).toHaveBeenCalledTimes(1);
        expect(setTagsMutate.mock.calls[0][0]).toEqual(['tier1']);
    });

    it('ignores non-Enter keys in the tag input', () => {
        render(<SecretDetailView secret={makeSecret()} />);
        const input = screen.getByPlaceholderText(/add a tag/i);
        fireEvent.keyDown(input, { key: 'a' });
        expect(setTagsMutate).not.toHaveBeenCalled();
    });

    it('does not add a blank tag on Enter', () => {
        render(<SecretDetailView secret={makeSecret()} />);
        const input = screen.getByPlaceholderText(/add a tag/i);
        fireEvent.keyDown(input, { key: 'Enter' });
        expect(setTagsMutate).not.toHaveBeenCalled();
    });

    it('does not add a duplicate tag (case-insensitive) and clears the draft', () => {
        render(<SecretDetailView secret={makeSecret()} />);
        const input = screen.getByPlaceholderText(/add a tag/i) as HTMLInputElement;
        fireEvent.change(input, { target: { value: 'PROD' } });
        fireEvent.keyDown(input, { key: 'Enter' });
        expect(setTagsMutate).not.toHaveBeenCalled();
        expect(input.value).toBe('');
    });
});

describe('SecretDetailView description', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        mockVersions = [];
        mockAccessors = [];
        mockAccessLog = [];
        mockAuditTrail = [];
        mockTags = [];
        mockDescription = 'the prod DB';
        setDescriptionMutate.mockClear();
        mockDescriptionState = { isPending: false };
    });

    it('shows the current description and saves an edit', () => {
        render(<SecretDetailView secret={makeSecret()} />);
        const box = screen.getByDisplayValue('the prod DB');
        // No Save until the value changes.
        expect(screen.queryByRole('button', { name: /^Save$/i })).not.toBeInTheDocument();
        fireEvent.change(box, { target: { value: 'the prod DB — contact dba@' } });
        fireEvent.click(screen.getByRole('button', { name: /^Save$/i }));
        expect(setDescriptionMutate).toHaveBeenCalledTimes(1);
        expect(setDescriptionMutate.mock.calls[0][0]).toBe('the prod DB — contact dba@');
    });

    it('discards a draft edit when Cancel is clicked', () => {
        render(<SecretDetailView secret={makeSecret()} />);
        const box = screen.getByDisplayValue('the prod DB');
        fireEvent.change(box, { target: { value: 'a different draft' } });
        expect(screen.getByRole('button', { name: /^Cancel$/i })).toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: /^Cancel$/i }));
        // Draft is discarded — back to the persisted description, no Save/Cancel shown.
        expect(screen.getByDisplayValue('the prod DB')).toBeInTheDocument();
        expect(screen.queryByRole('button', { name: /^Save$/i })).not.toBeInTheDocument();
        expect(setDescriptionMutate).not.toHaveBeenCalled();
    });

    it('shows a "Saving…" label on the Save button while the description mutation is pending', () => {
        // Type the draft while the mutation is idle (the textarea is disabled while
        // pending, so the edit must happen first); then flip to pending and re-render
        // to pick up the new mocked mutation state.
        const { rerender } = render(<SecretDetailView secret={makeSecret()} />);
        const box = screen.getByDisplayValue('the prod DB');
        fireEvent.change(box, { target: { value: 'a different draft' } });

        mockDescriptionState = { isPending: true };
        rerender(<SecretDetailView secret={makeSecret()} />);

        expect(screen.getByRole('button', { name: /Saving…/i })).toBeInTheDocument();
    });
});

// ─── Header: environment/rotation fallback text, and Edit/Share/Delete actions ──

describe('SecretDetailView header details and actions', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        mockVersions = [];
        mockAccessors = [];
        mockAccessLog = [];
        mockAuditTrail = [];
        mockTags = [];
    });

    it('shows "No environment" when the secret has no environment', () => {
        render(<SecretDetailView secret={makeSecret({ environment: '' })} />);
        expect(screen.getByText('No environment')).toBeInTheDocument();
    });

    it('shows a relative "Rotated … ago" label when lastRotatedAt is set', () => {
        const twoDaysAgo = new Date(Date.now() - (2 * 86_400_000 + 3_600_000)).toISOString();
        render(<SecretDetailView secret={makeSecret({ lastRotatedAt: twoDaysAgo })} />);
        expect(screen.getByText('Rotated 2 days ago')).toBeInTheDocument();
    });

    it('shows "Never rotated" when lastRotatedAt is absent', () => {
        render(<SecretDetailView secret={makeSecret()} />);
        expect(screen.getByText('Never rotated')).toBeInTheDocument();
    });

    it('calls onEdit, onShare, and onDelete with the secret when their buttons are clicked', () => {
        const onEdit = vi.fn();
        const onShare = vi.fn();
        const onDelete = vi.fn();
        const secret = makeSecret();
        render(<SecretDetailView secret={secret} onEdit={onEdit} onShare={onShare} onDelete={onDelete} />);

        fireEvent.click(screen.getByRole('button', { name: /^Edit$/i }));
        expect(onEdit).toHaveBeenCalledWith(secret);

        fireEvent.click(screen.getByRole('button', { name: /^Share$/i }));
        expect(onShare).toHaveBeenCalledWith(secret);

        fireEvent.click(screen.getByRole('button', { name: /^Delete$/i }));
        expect(onDelete).toHaveBeenCalledWith(secret);
    });

    it('calls onClose when the Close button is clicked', () => {
        const onClose = vi.fn();
        render(<SecretDetailView secret={makeSecret()} onClose={onClose} />);
        fireEvent.click(screen.getByRole('button', { name: /^Close$/i }));
        expect(onClose).toHaveBeenCalledTimes(1);
    });

    it('falls back to the "text" type color for an unrecognized secret type', () => {
        const weirdType = 'weird-type' as unknown as Secret['type'];
        render(<SecretDetailView secret={makeSecret({ type: weirdType })} />);
        const badge = screen.getByText('weird-type');
        expect(badge.className).toContain('bg-blue-100'); // TYPE_COLORS['text']
    });
});

// ─── Secret value reveal: loading/error/empty/plain/json states ────────────────

describe('SecretDetailView secret value reveal', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        mockVersions = [];
        mockVersionsLoading = false;
        mockVersionsError = null;
        mockAccessors = [];
        mockAccessLog = [];
        mockAuditTrail = [];
        mockTags = [];
    });

    it('reveals the decoded plaintext value and copies it to the clipboard', async () => {
        mockVersions = [{ VersionNumber: 1, EncryptedValue: btoa('sup3r-secret'), CreatedAt: '2026-06-10T00:00:00Z' }];
        render(<SecretDetailView secret={makeSecret()} />);

        fireEvent.click(screen.getByRole('button', { name: /^Reveal$/i }));
        expect(screen.getByText('sup3r-secret')).toBeInTheDocument();
        expect(screen.getByRole('button', { name: /^Hide$/i })).toBeInTheDocument();

        // Two buttons named "Copy" exist: the header's "copy to another environment"
        // action, and the value panel's "copy the revealed value" action (last in the DOM).
        const copyButtons = screen.getAllByRole('button', { name: /^Copy$/i });
        expect(copyButtons).toHaveLength(2);
        fireEvent.click(copyButtons[copyButtons.length - 1]!);

        await waitFor(() => expect(screen.getByText('Copied!')).toBeInTheDocument());
        expect(screen.getByText('Secret value copied to clipboard.')).toBeInTheDocument();
    });

    it('logs and does not crash when the clipboard write fails', async () => {
        const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
        const writeTextSpy = vi.spyOn(navigator.clipboard, 'writeText').mockRejectedValueOnce(new Error('denied'));
        mockVersions = [{ VersionNumber: 1, EncryptedValue: btoa('sup3r-secret'), CreatedAt: '2026-06-10T00:00:00Z' }];
        render(<SecretDetailView secret={makeSecret()} />);

        fireEvent.click(screen.getByRole('button', { name: /^Reveal$/i }));
        const copyButtons = screen.getAllByRole('button', { name: /^Copy$/i });
        fireEvent.click(copyButtons[copyButtons.length - 1]!);

        await waitFor(() =>
            expect(consoleErrorSpy).toHaveBeenCalledWith('Failed to copy to clipboard:', expect.any(Error))
        );
        expect(screen.queryByText('Copied!')).not.toBeInTheDocument();

        writeTextSpy.mockRestore();
        consoleErrorSpy.mockRestore();
    });

    it('shows a loading state while the value is being fetched', () => {
        mockVersionsLoading = true;
        mockVersions = [{ VersionNumber: 1, EncryptedValue: btoa('x'), CreatedAt: '2026-06-10T00:00:00Z' }];
        render(<SecretDetailView secret={makeSecret()} />);
        fireEvent.click(screen.getByRole('button', { name: /Reveal/i }));
        expect(screen.getByText('Loading...')).toBeInTheDocument();
    });

    it('shows an error alert when the value fails to load', () => {
        mockVersionsError = new Error('network down');
        render(<SecretDetailView secret={makeSecret()} />);
        fireEvent.click(screen.getByRole('button', { name: /^Reveal$/i }));
        expect(screen.getByText('Failed to load secret value')).toBeInTheDocument();
    });

    it('shows nothing when revealed but there are no versions', () => {
        mockVersions = [];
        render(<SecretDetailView secret={makeSecret()} />);
        fireEvent.click(screen.getByRole('button', { name: /^Reveal$/i }));
        expect(screen.queryByText(/Secret value is hidden/i)).not.toBeInTheDocument();
        // Only the header's unrelated "copy to another environment" button remains —
        // the value panel's copy-the-revealed-value button never appears.
        expect(screen.getAllByRole('button', { name: /^Copy$/i })).toHaveLength(1);
    });

    it('pretty-prints a valid JSON value', () => {
        mockVersions = [
            { VersionNumber: 1, EncryptedValue: btoa(JSON.stringify({ a: 1 })), CreatedAt: '2026-06-10T00:00:00Z' },
        ];
        render(<SecretDetailView secret={makeSecret({ type: 'json' })} />);
        fireEvent.click(screen.getByRole('button', { name: /^Reveal$/i }));
        expect(screen.getByText(/"a": 1/)).toBeInTheDocument();
    });

    it('falls back to the raw value when JSON parsing fails', () => {
        mockVersions = [{ VersionNumber: 1, EncryptedValue: btoa('not-json'), CreatedAt: '2026-06-10T00:00:00Z' }];
        render(<SecretDetailView secret={makeSecret({ type: 'json' })} />);
        fireEvent.click(screen.getByRole('button', { name: /^Reveal$/i }));
        expect(screen.getByText('not-json')).toBeInTheDocument();
    });
});

// ─── Certificate panel (ADR-054) — only mounted for certificate-typed secrets ───

describe('SecretDetailView certificate panel', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        mockVersions = [];
        mockAccessors = [];
        mockAccessLog = [];
        mockAuditTrail = [];
        mockTags = [];
        mockCertificate = { data: undefined, isLoading: false, isError: true };
    });

    it('does not mount the certificate panel for a non-certificate secret', () => {
        render(<SecretDetailView secret={makeSecret({ type: 'password' })} />);
        expect(screen.queryByText('Certificate')).not.toBeInTheDocument();
    });

    it('mounts the certificate panel for a certificate-typed secret', () => {
        mockCertificate = {
            isLoading: false,
            isError: false,
            data: {
                subject: 'CN=example.com',
                issuer: 'CN=Example CA',
                self_signed: false,
                not_before: '2026-01-01T00:00:00Z',
                not_after: '2027-01-01T00:00:00Z',
                dns_names: ['example.com'],
                serial_number: 'ab:cd',
                is_ca: false,
                signature_algorithm: 'SHA256-RSA',
                public_key_algorithm: 'RSA',
                is_expired: false,
                days_until_expiry: 120,
            },
        };
        render(<SecretDetailView secret={makeSecret({ type: 'certificate' })} />);
        expect(screen.getByText('Certificate')).toBeInTheDocument();
        expect(screen.getByText('CN=example.com')).toBeInTheDocument();
    });
});

// ─── Version rollback: pending + failure states ─────────────────────────────────

describe('SecretDetailView rollback pending/failure states', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        mockVersions = [
            { VersionNumber: 1, EncryptedValue: btoa('v1'), CreatedAt: '2026-06-10T00:00:00Z' },
            { VersionNumber: 2, EncryptedValue: btoa('v2'), CreatedAt: '2026-06-14T00:00:00Z' },
        ];
        mockAccessors = [];
        mockAccessLog = [];
        mockAuditTrail = [];
        mockTags = [];
        mockRollbackState = { isPending: false, isError: false, error: null };
    });

    it('shows "Rolling back…" and disables the button while pending', () => {
        mockRollbackState = { isPending: true, isError: false, error: null };
        render(<SecretDetailView secret={makeSecret()} />);
        const btn = screen.getByRole('button', { name: /Rolling back…/i });
        expect(btn).toBeDisabled();
    });

    it('shows the mutation error message when rollback fails with an Error', () => {
        mockRollbackState = { isPending: false, isError: true, error: new Error('version not found') };
        render(<SecretDetailView secret={makeSecret()} />);
        expect(screen.getByText('Rollback failed')).toBeInTheDocument();
        expect(screen.getByText('version not found')).toBeInTheDocument();
    });

    it('shows a generic error message when the rollback error is not an Error instance', () => {
        mockRollbackState = { isPending: false, isError: true, error: 'plain string error' };
        render(<SecretDetailView secret={makeSecret()} />);
        expect(screen.getByText('Rollback failed')).toBeInTheDocument();
        expect(screen.getByText('An unexpected error occurred')).toBeInTheDocument();
    });
});

// ─── Risk score panel ────────────────────────────────────────────────────────────

describe('SecretDetailView risk score', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        mockVersions = [];
        mockAccessors = [];
        mockAccessLog = [];
        mockAuditTrail = [];
        mockTags = [];
        mockRisk = null;
    });

    it('omits the panel when there is no risk data', () => {
        render(<SecretDetailView secret={makeSecret()} />);
        expect(screen.queryByText('Risk Score')).not.toBeInTheDocument();
    });

    it('renders the score, band, and per-factor bars across low/medium/high factor colors', () => {
        mockRisk = {
            score: 85,
            band: 'high',
            factors: [
                { key: 'age', label: 'Age', score: 10, weight: 0.2, detail: 'rotated recently' },
                { key: 'access', label: 'Access breadth', score: 50, weight: 0.3, detail: 'moderate' },
                { key: 'exposure', label: 'Exposure', score: 80, weight: 0.5, detail: 'widely shared' },
            ],
        };
        render(<SecretDetailView secret={makeSecret()} />);
        expect(screen.getByText('Risk Score')).toBeInTheDocument();
        expect(screen.getByText('85')).toBeInTheDocument();
        expect(screen.getByText('High risk')).toBeInTheDocument();
        expect(screen.getByText('Age')).toBeInTheDocument();
        expect(screen.getByText('Access breadth')).toBeInTheDocument();
        expect(screen.getByText('Exposure')).toBeInTheDocument();
        expect(screen.getByText('rotated recently')).toBeInTheDocument();
        expect(screen.getByText('20%')).toBeInTheDocument();
    });
});

// ─── Static tags / metadata / sharing / permissions panels ──────────────────────

describe('SecretDetailView static tags, metadata, sharing, and permissions panels', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        mockVersions = [];
        mockAccessors = [];
        mockAccessLog = [];
        mockAuditTrail = [];
        mockTags = [];
    });

    it('renders static secret.tags chips', () => {
        render(<SecretDetailView secret={makeSecret({ tags: ['legacy-flag'] })} />);
        expect(screen.getByText('legacy-flag')).toBeInTheDocument();
    });

    it('omits the static tags panel when there are no tags', () => {
        render(<SecretDetailView secret={makeSecret({ tags: [] })} />);
        // "Tags" heading is still present via the editable TagsEditPanel; scope to the chip only.
        expect(screen.queryByText('legacy-flag')).not.toBeInTheDocument();
    });

    it('renders metadata key/value rows', () => {
        render(<SecretDetailView secret={makeSecret({ metadata: { region: 'us-east-1' } })} />);
        expect(screen.getByText('Metadata')).toBeInTheDocument();
        expect(screen.getByText('region')).toBeInTheDocument();
        expect(screen.getByText('us-east-1')).toBeInTheDocument();
    });

    it('omits the metadata panel when metadata is empty', () => {
        render(<SecretDetailView secret={makeSecret({ metadata: {} })} />);
        expect(screen.queryByText('Metadata')).not.toBeInTheDocument();
    });

    it('renders sharing info and calls onShare from "Manage Shares"', () => {
        const onShare = vi.fn();
        const secret = makeSecret({ isShared: true, shareCount: 3 });
        render(<SecretDetailView secret={secret} onShare={onShare} />);
        expect(screen.getByText('Sharing')).toBeInTheDocument();
        expect(screen.getByText('3')).toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: /Manage Shares/i }));
        expect(onShare).toHaveBeenCalledWith(secret);
    });

    it('omits the sharing panel when the secret is not shared', () => {
        render(<SecretDetailView secret={makeSecret({ isShared: false })} />);
        expect(screen.queryByText('Sharing')).not.toBeInTheDocument();
    });

    it('renders permission chips', () => {
        render(<SecretDetailView secret={makeSecret({ permissions: ['read', 'write'] })} />);
        expect(screen.getByText('Permissions')).toBeInTheDocument();
        expect(screen.getByText('read')).toBeInTheDocument();
        expect(screen.getByText('write')).toBeInTheDocument();
    });

    it('omits the permissions panel when there are no permissions', () => {
        render(<SecretDetailView secret={makeSecret({ permissions: [] })} />);
        expect(screen.queryByText('Permissions')).not.toBeInTheDocument();
    });
});

// ─── Rotate-secret modal ──────────────────────────────────────────────────────────

describe('SecretDetailView rotate secret modal', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        mockVersions = [];
        mockAccessors = [];
        mockAccessLog = [];
        mockAuditTrail = [];
        mockTags = [];
        mockRotateState = { isPending: false, isError: false };
    });

    it('opens the modal from the header Rotate button and closes it on Cancel', () => {
        render(<SecretDetailView secret={makeSecret()} />);
        fireEvent.click(screen.getByRole('button', { name: /^Rotate$/i }));
        expect(screen.getByText('Rotate db-password')).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: /^Cancel$/i }));
        expect(screen.queryByText('Rotate db-password')).not.toBeInTheDocument();
        expect(mockRotateReset).toHaveBeenCalled();
    });

    it('submits the new value and closes the modal on success', () => {
        mockRotateMutate.mockImplementationOnce((_value: string, opts?: { onSuccess?: () => void }) => {
            opts?.onSuccess?.();
        });
        render(<SecretDetailView secret={makeSecret()} />);
        fireEvent.click(screen.getByRole('button', { name: /^Rotate$/i }));
        fireEvent.change(screen.getByLabelText('New value'), { target: { value: 'new-secret-value' } });
        fireEvent.click(screen.getByRole('button', { name: /Rotate secret/i }));

        expect(mockRotateMutate).toHaveBeenCalledWith('new-secret-value', expect.anything());
        expect(screen.queryByText('Rotate db-password')).not.toBeInTheDocument();
    });

    it('disables submit while the value is blank', () => {
        render(<SecretDetailView secret={makeSecret()} />);
        fireEvent.click(screen.getByRole('button', { name: /^Rotate$/i }));
        expect(screen.getByRole('button', { name: /Rotate secret/i })).toBeDisabled();
    });

    it('shows a failure alert when rotation errors', () => {
        mockRotateState = { isPending: false, isError: true };
        render(<SecretDetailView secret={makeSecret()} />);
        fireEvent.click(screen.getByRole('button', { name: /^Rotate$/i }));
        expect(screen.getByText('Rotation failed')).toBeInTheDocument();
    });

    it('shows a pending state and disables inputs while rotating', () => {
        mockRotateState = { isPending: true, isError: false };
        render(<SecretDetailView secret={makeSecret()} />);
        fireEvent.click(screen.getByRole('button', { name: /^Rotate$/i }));
        expect(screen.getByText('Rotating…')).toBeInTheDocument();
        expect(screen.getByLabelText('New value')).toBeDisabled();
        expect(screen.getByRole('button', { name: /^Cancel$/i })).toBeDisabled();
    });
});

// ─── Copy secret to another environment (window.prompt flow) ────────────────────

describe('SecretDetailView copy to another environment', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        mockVersions = [];
        mockAccessors = [];
        mockAccessLog = [];
        mockAuditTrail = [];
        mockTags = [];
        mockCopyState = { isPending: false };
    });

    it('copies to the entered environment with a custom name', () => {
        const promptSpy = vi.spyOn(window, 'prompt').mockReturnValueOnce('5').mockReturnValueOnce('db-password-copy');
        mockCopyMutate.mockImplementationOnce((_payload: unknown, opts?: { onSuccess?: () => void }) => {
            opts?.onSuccess?.();
        });
        render(<SecretDetailView secret={makeSecret()} />);
        fireEvent.click(screen.getByRole('button', { name: /^Copy$/i }));
        expect(mockCopyMutate).toHaveBeenCalledWith({ environmentId: 5, name: 'db-password-copy' }, expect.anything());
        expect(screen.getByText('Copied to environment 5.')).toBeInTheDocument();
        promptSpy.mockRestore();
    });

    it('omits the name field when the name prompt is left blank', () => {
        const promptSpy = vi.spyOn(window, 'prompt').mockReturnValueOnce('5').mockReturnValueOnce('');
        render(<SecretDetailView secret={makeSecret()} />);
        fireEvent.click(screen.getByRole('button', { name: /^Copy$/i }));
        expect(mockCopyMutate).toHaveBeenCalledWith({ environmentId: 5 }, expect.anything());
        promptSpy.mockRestore();
    });

    it('does not copy when the environment prompt is cancelled', () => {
        const promptSpy = vi.spyOn(window, 'prompt').mockReturnValueOnce(null);
        render(<SecretDetailView secret={makeSecret()} />);
        fireEvent.click(screen.getByRole('button', { name: /^Copy$/i }));
        expect(mockCopyMutate).not.toHaveBeenCalled();
        promptSpy.mockRestore();
    });

    it('does not copy when the environment id is not a positive integer', () => {
        const promptSpy = vi.spyOn(window, 'prompt').mockReturnValueOnce('not-a-number');
        render(<SecretDetailView secret={makeSecret()} />);
        fireEvent.click(screen.getByRole('button', { name: /^Copy$/i }));
        expect(mockCopyMutate).not.toHaveBeenCalled();
        promptSpy.mockRestore();
    });

    it('does not copy when the environment id is zero or negative', () => {
        const promptSpy = vi.spyOn(window, 'prompt').mockReturnValueOnce('0');
        render(<SecretDetailView secret={makeSecret()} />);
        fireEvent.click(screen.getByRole('button', { name: /^Copy$/i }));
        expect(mockCopyMutate).not.toHaveBeenCalled();
        promptSpy.mockRestore();
    });

    it('shows the server-provided error message when the copy mutation fails', () => {
        const promptSpy = vi.spyOn(window, 'prompt').mockReturnValueOnce('5').mockReturnValueOnce('');
        mockCopyMutate.mockImplementationOnce((_payload: unknown, opts?: { onError?: (err: unknown) => void }) => {
            opts?.onError?.({ response: { data: { message: 'Quota exceeded' } } });
        });
        render(<SecretDetailView secret={makeSecret()} />);
        fireEvent.click(screen.getByRole('button', { name: /^Copy$/i }));
        expect(screen.getByText('Quota exceeded')).toBeInTheDocument();
        promptSpy.mockRestore();
    });

    it('falls back to a generic message when the copy error has no server message', () => {
        const promptSpy = vi.spyOn(window, 'prompt').mockReturnValueOnce('5').mockReturnValueOnce('');
        mockCopyMutate.mockImplementationOnce((_payload: unknown, opts?: { onError?: (err: unknown) => void }) => {
            opts?.onError?.({});
        });
        render(<SecretDetailView secret={makeSecret()} />);
        fireEvent.click(screen.getByRole('button', { name: /^Copy$/i }));
        expect(screen.getByText('Copy failed.')).toBeInTheDocument();
        promptSpy.mockRestore();
    });
});
