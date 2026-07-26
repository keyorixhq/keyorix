import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '../../../test/test-utils';
import { ProjectAccessReviewCampaigns } from '../ProjectAccessReviewCampaigns';

const mockUseCampaigns = vi.fn();
const mockUseCampaign = vi.fn();
const mockOpenMutate = vi.fn();
const mockDecideMutate = vi.fn();
const mockCloseMutate = vi.fn();
const mockGet = vi.fn();

vi.mock('../../../features/projects/api', () => ({
    useAccessReviewCampaigns: () => mockUseCampaigns(),
    useAccessReviewCampaign: () => mockUseCampaign(),
    useOpenCampaign: () => ({ mutate: mockOpenMutate, isPending: false }),
    useDecideCampaignItem: () => ({ mutate: mockDecideMutate, isPending: false }),
    useCloseCampaign: () => ({ mutate: mockCloseMutate, isPending: false }),
}));

vi.mock('../../../services/client', () => ({
    apiClient: { get: (...args: any[]) => mockGet(...args) },
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
        {
            id: 10,
            principalType: 'user',
            principalId: 5,
            principalName: 'alice',
            email: 'a@x.io',
            source: 'role',
            roleName: 'editor',
            accessLevel: 'write',
            secretName: '',
            decision: 'pending',
        },
        {
            id: 11,
            principalType: 'group',
            principalId: 9,
            principalName: 'devs',
            email: '',
            source: 'group_share',
            roleName: '',
            accessLevel: 'read',
            secretName: 'db',
            decision: 'attested',
        },
    ],
};

describe('ProjectAccessReviewCampaigns', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        mockUseCampaign.mockReturnValue({ data: detail, isLoading: false });
        // jsdom has no object-URL API; stub it for the CSV download.
        (URL as any).createObjectURL = vi.fn(() => 'blob:mock');
        (URL as any).revokeObjectURL = vi.fn();
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
            expect.any(Object)
        );
    });

    it('shows an empty state with no campaigns', () => {
        mockUseCampaigns.mockReturnValue({ data: [], isLoading: false });
        render(<ProjectAccessReviewCampaigns projectId={2} />);
        expect(screen.getByText(/No campaigns yet/i)).toBeInTheDocument();
    });

    it('downloads the campaign CSV as a blob when Download CSV is clicked', async () => {
        mockGet.mockResolvedValue({ data: new Blob(['principal\n'], { type: 'text/csv' }) });
        mockUseCampaigns.mockReturnValue({ data: campaigns, isLoading: false });
        render(<ProjectAccessReviewCampaigns projectId={2} />);
        fireEvent.click(screen.getByText('Review'));
        fireEvent.click(screen.getByRole('button', { name: /download csv/i }));

        await waitFor(() =>
            expect(mockGet).toHaveBeenCalledWith('/api/v1/projects/2/access-review/campaigns/1/export.csv', {
                responseType: 'blob',
            })
        );
        expect((URL as any).createObjectURL).toHaveBeenCalled();
    });
});
