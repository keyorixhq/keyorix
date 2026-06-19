import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '../../../test/test-utils';
import { MachineTokenHygieneSection } from '../MachineTokenHygieneSection';

const fiveDaysAgo = new Date(Date.now() - 5 * 24 * 60 * 60 * 1000).toISOString();

let mockTokens: any[] = [];
vi.mock('../api', () => ({
    useStaleMachineTokens: () => ({ data: mockTokens }),
}));

describe('MachineTokenHygieneSection', () => {
    it('renders nothing when there are no flagged tokens', () => {
        mockTokens = [];
        const { container } = render(<MachineTokenHygieneSection />);
        expect(container).toBeEmptyDOMElement();
    });

    it('renders the count, per-token detail, and flag labels', () => {
        mockTokens = [
            { id: 2, machine_identity_id: 5, name: 'ci', token_prefix: 'kx_machine_ci', last_used_at: null, expired: false, stale: true },
            { id: 7, machine_identity_id: 9, name: 'old', token_prefix: 'kx_machine_old', last_used_at: fiveDaysAgo, expired: true, stale: false },
        ];
        render(<MachineTokenHygieneSection />);
        expect(screen.getByText(/2 machine tokens stale or expired-but-active/i)).toBeInTheDocument();
        expect(screen.getByText('stale')).toBeInTheDocument();
        expect(screen.getByText('expired')).toBeInTheDocument();
        expect(screen.getByText(/machine #5 · never used/i)).toBeInTheDocument();
        expect(screen.getByText(/machine #9 · used 5 days ago/i)).toBeInTheDocument();
    });

    it('can be dismissed', () => {
        mockTokens = [
            { id: 2, machine_identity_id: 5, name: 'ci', token_prefix: 'kx_machine_ci', last_used_at: null, expired: false, stale: true },
        ];
        render(<MachineTokenHygieneSection />);
        fireEvent.click(screen.getByRole('button', { name: /dismiss/i }));
        expect(screen.queryByText(/machine token/i)).not.toBeInTheDocument();
    });
});
