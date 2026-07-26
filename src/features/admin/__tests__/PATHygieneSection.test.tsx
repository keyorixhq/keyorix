import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '../../../test/test-utils';
import { PATHygieneSection } from '../PATHygieneSection';

const fiveDaysAgo = new Date(Date.now() - 5 * 24 * 60 * 60 * 1000).toISOString();

let mockTokens: any[] = [];
vi.mock('../api', () => ({
    useStalePATs: () => ({ data: mockTokens }),
}));

describe('PATHygieneSection', () => {
    it('renders nothing when there are no flagged tokens', () => {
        mockTokens = [];
        const { container } = render(<PATHygieneSection />);
        expect(container).toBeEmptyDOMElement();
    });

    it('renders the count, per-token detail, and flag labels', () => {
        mockTokens = [
            {
                id: 2,
                name: 'ci',
                token_prefix: 'kx_pat_ci',
                user_id: 7,
                last_used_at: null,
                expired: false,
                stale: true,
            },
            {
                id: 5,
                name: 'old',
                token_prefix: 'kx_pat_old',
                user_id: 9,
                last_used_at: fiveDaysAgo,
                expired: true,
                stale: false,
            },
        ];
        render(<PATHygieneSection />);
        expect(screen.getByText(/2 personal access tokens stale or expired-but-active/i)).toBeInTheDocument();
        expect(screen.getByText('stale')).toBeInTheDocument();
        expect(screen.getByText('expired')).toBeInTheDocument();
        expect(screen.getByText(/user #7 · never used/i)).toBeInTheDocument();
        expect(screen.getByText(/user #9 · used 5 days ago/i)).toBeInTheDocument();
    });

    it('can be dismissed', () => {
        mockTokens = [
            {
                id: 2,
                name: 'ci',
                token_prefix: 'kx_pat_ci',
                user_id: 7,
                last_used_at: null,
                expired: false,
                stale: true,
            },
        ];
        render(<PATHygieneSection />);
        fireEvent.click(screen.getByRole('button', { name: /dismiss/i }));
        expect(screen.queryByText(/personal access token/i)).not.toBeInTheDocument();
    });
});
