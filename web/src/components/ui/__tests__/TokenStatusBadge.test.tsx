import React from 'react';
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { TokenStatusBadge, getTokenStatus, type TokenStatus } from '../TokenStatusBadge';

describe('getTokenStatus', () => {
    it('returns "revoked" when the token is revoked, regardless of expiry', () => {
        expect(getTokenStatus({ revoked: true, expires_at: '2099-01-01T00:00:00Z' })).toBe('revoked');
    });

    it('returns "expired" when expires_at is in the past', () => {
        expect(getTokenStatus({ revoked: false, expires_at: '2000-01-01T00:00:00Z' })).toBe('expired');
    });

    it('returns "active" when not revoked and not expired', () => {
        expect(getTokenStatus({ revoked: false, expires_at: '2099-01-01T00:00:00Z' })).toBe('active');
    });

    it('returns "active" when there is no expiry date', () => {
        expect(getTokenStatus({ revoked: false, expires_at: null })).toBe('active');
        expect(getTokenStatus({ revoked: false })).toBe('active');
    });
});

describe('TokenStatusBadge', () => {
    const labels: Record<TokenStatus, string> = { active: 'Active', revoked: 'Revoked', expired: 'Expired' };

    it.each(['active', 'revoked', 'expired'] as TokenStatus[])('renders the %s label', (status) => {
        render(<TokenStatusBadge status={status} isDark={false} />);
        expect(screen.getByText(labels[status])).toBeInTheDocument();
    });

    it('renders light-mode styling', () => {
        render(<TokenStatusBadge status="active" isDark={false} />);
        expect(screen.getByText('Active')).toHaveStyle({ backgroundColor: '#dcfce7', color: '#166534' });
    });

    it('renders dark-mode styling', () => {
        render(<TokenStatusBadge status="active" isDark />);
        expect(screen.getByText('Active')).toHaveStyle({ backgroundColor: 'rgba(16,185,129,0.15)', color: '#34d399' });
    });
});
