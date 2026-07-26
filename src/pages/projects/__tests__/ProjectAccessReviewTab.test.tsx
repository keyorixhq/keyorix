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
});
