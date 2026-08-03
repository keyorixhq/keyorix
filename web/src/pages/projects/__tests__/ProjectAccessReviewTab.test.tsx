import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '../../../test/test-utils';
import { ProjectAccessReviewTab } from '../ProjectAccessReviewTab';

const mockUseAccessReview = vi.fn();
const mockAttestMutate = vi.fn();
const mockRevokeMutate = vi.fn();

vi.mock('../../../features/projects/api', () => ({
    useAccessReview: (projectId: number) => mockUseAccessReview(projectId),
    useAttestAccessReview: () => ({ mutate: mockAttestMutate, isPending: false }),
    useRevokeAccessReview: () => ({ mutate: mockRevokeMutate, isPending: false }),
    // The tab mounts the campaigns section; stub its hooks so it renders its empty state.
    useAccessReviewCampaigns: () => ({ data: [], isLoading: false }),
    useAccessReviewCampaign: () => ({ data: null, isLoading: false }),
    useOpenCampaign: () => ({ mutate: vi.fn(), isPending: false }),
    useDecideCampaignItem: () => ({ mutate: vi.fn(), isPending: false }),
    useCloseCampaign: () => ({ mutate: vi.fn(), isPending: false }),
}));

const entries = [
    {
        principalType: 'user',
        principalId: 10,
        principalName: 'alice',
        email: 'alice@x.io',
        source: 'role',
        roleId: 3,
        roleName: 'editor',
        accessLevel: 'write',
        environmentId: 0,
    },
    {
        principalType: 'user',
        principalId: 11,
        principalName: 'bob',
        email: 'bob@x.io',
        source: 'owner',
        accessLevel: 'owner',
        secretId: 500,
        secretName: 'db-pw',
    },
    {
        principalType: 'group',
        principalId: 100,
        principalName: 'devs',
        source: 'group_share',
        accessLevel: 'read',
        secretId: 500,
        secretName: 'db-pw',
    },
];

describe('ProjectAccessReviewTab', () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    it('lists each grant with its source, principal, and access level', () => {
        mockUseAccessReview.mockReturnValue({ isLoading: false, isError: false, data: entries });
        render(<ProjectAccessReviewTab projectId={1} />);

        expect(screen.getByText(/alice \(alice@x.io\)/)).toBeInTheDocument();
        expect(screen.getByText('Role')).toBeInTheDocument();
        expect(screen.getByText(/Role: editor \(project-wide\)/)).toBeInTheDocument();
        expect(screen.getByText('devs')).toBeInTheDocument();
        expect(screen.getByText('Group share')).toBeInTheDocument();
        // The owner row is present...
        expect(screen.getByText('Owner')).toBeInTheDocument();
    });

    it('offers Attest for every grant but Revoke only for non-owner grants', () => {
        mockUseAccessReview.mockReturnValue({ isLoading: false, isError: false, data: entries });
        render(<ProjectAccessReviewTab projectId={1} />);

        // 3 entries → 3 Attest buttons; owner is not revocable → 2 Revoke buttons.
        expect(screen.getAllByText('Attest')).toHaveLength(3);
        expect(screen.getAllByText('Revoke')).toHaveLength(2);
    });

    it('attests a grant with the decision derived from the entry', () => {
        mockUseAccessReview.mockReturnValue({ isLoading: false, isError: false, data: [entries[0]] });
        render(<ProjectAccessReviewTab projectId={1} />);

        fireEvent.click(screen.getByText('Attest'));
        expect(mockAttestMutate).toHaveBeenCalledWith(
            expect.objectContaining({ source: 'role', principalId: 10, roleId: 3 }),
            expect.any(Object)
        );
    });

    it('requires a confirmation before revoking', () => {
        mockUseAccessReview.mockReturnValue({ isLoading: false, isError: false, data: [entries[2]] });
        render(<ProjectAccessReviewTab projectId={1} />);

        // First click reveals Confirm; it does not revoke yet.
        fireEvent.click(screen.getByText('Revoke'));
        expect(mockRevokeMutate).not.toHaveBeenCalled();
        fireEvent.click(screen.getByText('Confirm'));
        expect(mockRevokeMutate).toHaveBeenCalledWith(
            expect.objectContaining({ source: 'group_share', principalId: 100, secretId: 500 }),
            expect.any(Object)
        );
    });

    it('shows an empty state when no one has access', () => {
        mockUseAccessReview.mockReturnValue({ isLoading: false, isError: false, data: [] });
        render(<ProjectAccessReviewTab projectId={1} />);
        expect(screen.getByText(/No one has access/i)).toBeInTheDocument();
    });

    it('shows a loading skeleton while the review is in flight', () => {
        mockUseAccessReview.mockReturnValue({ isLoading: true, isError: false, data: [] });
        const { container } = render(<ProjectAccessReviewTab projectId={1} />);
        expect(container.querySelectorAll('.animate-pulse').length).toBeGreaterThan(0);
        expect(screen.queryByText(/No one has access/i)).not.toBeInTheDocument();
    });

    it('shows an error message when the review fails to load', () => {
        mockUseAccessReview.mockReturnValue({ isLoading: false, isError: true, data: [] });
        render(<ProjectAccessReviewTab projectId={1} />);
        expect(screen.getByText('Failed to load the access review.')).toBeInTheDocument();
    });

    it('marks a grant Attested after a successful attest, and shows an error on failure', () => {
        mockUseAccessReview.mockReturnValue({ isLoading: false, isError: false, data: [entries[0]] });
        mockAttestMutate.mockImplementationOnce((_decision, opts) => opts.onSuccess());
        render(<ProjectAccessReviewTab projectId={1} />);

        fireEvent.click(screen.getByText('Attest'));
        expect(screen.getByText('Attested')).toBeInTheDocument();
    });

    it('shows an error banner when attest fails', () => {
        mockUseAccessReview.mockReturnValue({ isLoading: false, isError: false, data: [entries[0]] });
        mockAttestMutate.mockImplementationOnce((_decision, opts) =>
            opts.onError({ response: { data: { error: 'attest failed' } } })
        );
        render(<ProjectAccessReviewTab projectId={1} />);

        fireEvent.click(screen.getByText('Attest'));
        expect(screen.getByText('attest failed')).toBeInTheDocument();
    });

    it('cancels a pending revoke confirmation without revoking', () => {
        mockUseAccessReview.mockReturnValue({ isLoading: false, isError: false, data: [entries[2]] });
        render(<ProjectAccessReviewTab projectId={1} />);

        fireEvent.click(screen.getByText('Revoke'));
        fireEvent.click(screen.getByText('Cancel'));
        expect(screen.getByText('Revoke')).toBeInTheDocument();
        expect(mockRevokeMutate).not.toHaveBeenCalled();
    });

    it('shows an error banner when revoke fails', () => {
        mockUseAccessReview.mockReturnValue({ isLoading: false, isError: false, data: [entries[2]] });
        mockRevokeMutate.mockImplementationOnce((_decision, opts) =>
            opts.onError({ response: { data: { message: 'revoke failed' } } })
        );
        render(<ProjectAccessReviewTab projectId={1} />);

        fireEvent.click(screen.getByText('Revoke'));
        fireEvent.click(screen.getByText('Confirm'));
        expect(screen.getByText('revoke failed')).toBeInTheDocument();
    });

    it('falls back to a generic "Action failed" message with no error payload', () => {
        mockUseAccessReview.mockReturnValue({ isLoading: false, isError: false, data: [entries[0]] });
        mockAttestMutate.mockImplementationOnce((_decision, opts) => opts.onError({}));
        render(<ProjectAccessReviewTab projectId={1} />);

        fireEvent.click(screen.getByText('Attest'));
        expect(screen.getByText('Action failed.')).toBeInTheDocument();
    });

    it('shows scoped-to-environment role detail, an unmapped source label, and access-level fallback', () => {
        const scopedRoleEntry = {
            principalType: 'user',
            principalId: 20,
            principalName: 'carol',
            email: '',
            source: 'weird_source',
            roleId: 4,
            roleName: '',
            accessLevel: '',
            environmentId: 7,
        };
        mockUseAccessReview.mockReturnValue({ isLoading: false, isError: false, data: [scopedRoleEntry] });
        render(<ProjectAccessReviewTab projectId={1} />);

        // Unmapped source falls back to the raw value.
        expect(screen.getByText('weird_source')).toBeInTheDocument();
        // No principalName? carol has one, so this exercises the plain-name path with no email.
        expect(screen.getByText('carol')).toBeInTheDocument();
        // Access level falls back to an em dash when blank, as does the (non-role) source detail
        // since there's no secretName either — both render as "—".
        expect(screen.getAllByText('—').length).toBe(2);
    });

    it('scopes role detail to an environment when one is set, and falls back for a missing principal name', () => {
        const envScopedRole = {
            principalType: 'user',
            principalId: 21,
            principalName: '',
            email: '',
            source: 'role',
            roleId: 5,
            roleName: 'viewer',
            accessLevel: 'read',
            environmentId: 9,
        };
        mockUseAccessReview.mockReturnValue({ isLoading: false, isError: false, data: [envScopedRole] });
        render(<ProjectAccessReviewTab projectId={1} />);

        expect(screen.getByText(/Role: viewer \(env 9\)/)).toBeInTheDocument();
        // No principalName -> falls back to "<type> <id>".
        expect(screen.getByText('user 21')).toBeInTheDocument();
    });

    it('falls back to an em dash for a non-role grant with no secret name', () => {
        const noSecretEntry = {
            principalType: 'group',
            principalId: 30,
            principalName: 'ops',
            source: 'group_share',
            accessLevel: 'read',
        };
        mockUseAccessReview.mockReturnValue({ isLoading: false, isError: false, data: [noSecretEntry] });
        render(<ProjectAccessReviewTab projectId={1} />);
        expect(screen.getByText('—')).toBeInTheDocument();
    });
});
