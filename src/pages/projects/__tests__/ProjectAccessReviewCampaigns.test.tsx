import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '../../../test/test-utils';
import { ProjectAccessReviewCampaigns } from '../ProjectAccessReviewCampaigns';

const mockUseCampaigns = vi.fn();
const mockUseCampaign = vi.fn();
const mockOpenMutate = vi.fn();
const mockDecideMutate = vi.fn();
const mockCloseMutate = vi.fn();

vi.mock('../../../features/projects/api', () => ({
    useAccessReviewCampaigns: () => mockUseCampaigns(),
    useAccessReviewCampaign: () => mockUseCampaign(),
    useOpenCampaign: () => ({ mutate: mockOpenMutate, isPending: false }),
    useDecideCampaignItem: () => ({ mutate: mockDecideMutate, isPending: false }),
    useCloseCampaign: () => ({ mutate: mockCloseMutate, isPending: false }),
}));

const campaigns = [
    {
        campaign: { id: 1, projectId: 2, name: 'Q4 2026', state: 'open', createdAt: '' },
        progress: { total: 3, pending: 2, attested: 1, revoked: 0 },
    },
];

const detail = {
    campaign: { id: 1, projectId: 2, name: 'Q4 2026', state: 'open', createdAt: '' },
    progress: { total: 3, pending: 2, attested: 1, revoked: 0 },
    items: [
        { id: 10, principalType: 'user', principalId: 5, principalName: 'alice', email: 'a@x.io', source: 'role', roleName: 'editor', accessLevel: 'write', secretName: '', decision: 'pending' },
        { id: 11, principalType: 'group', principalId: 9, principalName: 'devs', email: '', source: 'group_share', roleName: '', accessLevel: 'read', secretName: 'db', decision: 'attested' },
    ],
};

describe('ProjectAccessReviewCampaigns', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        mockUseCampaign.mockReturnValue({ data: detail, isLoading: false });
    });

    it('lists campaigns with state and progress', () => {
        mockUseCampaigns.mockReturnValue({ data: campaigns, isLoading: false });
        render(<ProjectAccessReviewCampaigns projectId={2} />);
        expect(screen.getByText('Q4 2026')).toBeInTheDocument();
        expect(screen.getByText('open')).toBeInTheDocument();
        expect(screen.getByText(/1\/3 decided · 1 attested · 0 revoked/)).toBeInTheDocument();
    });

    it('opens a campaign with the typed name', () => {
        mockUseCampaigns.mockReturnValue({ data: [], isLoading: false });
        render(<ProjectAccessReviewCampaigns projectId={2} />);
        fireEvent.change(screen.getByPlaceholderText('Campaign name'), { target: { value: 'Annual review' } });
        fireEvent.click(screen.getByText('Open'));
        expect(mockOpenMutate).toHaveBeenCalledWith('Annual review', expect.any(Object));
    });

    it('reveals items and attests a pending one', () => {
        mockUseCampaigns.mockReturnValue({ data: campaigns, isLoading: false });
        render(<ProjectAccessReviewCampaigns projectId={2} />);
        fireEvent.click(screen.getByText('Review'));
        // The pending item's principal is shown, and an Attest control is available.
        expect(screen.getByText(/alice/)).toBeInTheDocument();
        fireEvent.click(screen.getByText('Attest'));
        expect(mockDecideMutate).toHaveBeenCalledWith(
            expect.objectContaining({ itemId: 10, action: 'attest' }),
            expect.any(Object),
        );
    });

    it('shows an empty state with no campaigns', () => {
        mockUseCampaigns.mockReturnValue({ data: [], isLoading: false });
        render(<ProjectAccessReviewCampaigns projectId={2} />);
        expect(screen.getByText(/No campaigns yet/i)).toBeInTheDocument();
    });
});
