import { describe, it, expect } from 'vitest';
import { render, screen } from '../../../test/test-utils';
import { AccountStateBadge } from '../AccountStateBadge';

describe('AccountStateBadge', () => {
    it('labels each account state', () => {
        const { rerender } = render(<AccountStateBadge state="active" />);
        expect(screen.getByText('Active')).toBeInTheDocument();
        rerender(<AccountStateBadge state="pending_first_login" />);
        expect(screen.getByText('Pending setup')).toBeInTheDocument();
        rerender(<AccountStateBadge state="password_reset_required" />);
        expect(screen.getByText('Reset required')).toBeInTheDocument();
        rerender(<AccountStateBadge state="suspended" />);
        expect(screen.getByText('Suspended')).toBeInTheDocument();
    });

    it('shows Deleted regardless of state when deleted', () => {
        render(<AccountStateBadge state="active" deleted />);
        expect(screen.getByText('Deleted')).toBeInTheDocument();
        expect(screen.queryByText('Active')).not.toBeInTheDocument();
    });

    it('defaults an unknown/empty state to Active', () => {
        render(<AccountStateBadge />);
        expect(screen.getByText('Active')).toBeInTheDocument();
    });

    it('falls back to the raw state string for a state with no known label/style', () => {
        render(<AccountStateBadge state="some_new_state" />);
        expect(screen.getByText('some_new_state')).toBeInTheDocument();
    });
});
