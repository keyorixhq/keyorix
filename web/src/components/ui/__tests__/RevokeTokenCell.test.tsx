import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { RevokeTokenCell } from '../RevokeTokenCell';

function setup(overrides: Partial<React.ComponentProps<typeof RevokeTokenCell>> = {}) {
    const props = {
        isPending: false,
        isMutating: false,
        inactive: false,
        isDark: false,
        onRevoke: vi.fn(),
        onCancel: vi.fn(),
        onSetPending: vi.fn(),
        ...overrides,
    };
    render(<RevokeTokenCell {...props} />);
    return props;
}

describe('RevokeTokenCell', () => {
    it('renders a "Revoke" trigger button when not pending', () => {
        setup();
        expect(screen.getByRole('button', { name: 'Revoke' })).toBeInTheDocument();
    });

    it('calls onSetPending when the trigger button is clicked', () => {
        const props = setup();
        fireEvent.click(screen.getByRole('button', { name: 'Revoke' }));
        expect(props.onSetPending).toHaveBeenCalledOnce();
    });

    it('disables the trigger button when inactive', () => {
        setup({ inactive: true });
        expect(screen.getByRole('button', { name: 'Revoke' })).toBeDisabled();
    });

    it('updates the background color on hover when active (light mode)', () => {
        setup({ inactive: false, isDark: false });
        const button = screen.getByRole('button', { name: 'Revoke' });
        fireEvent.mouseEnter(button);
        expect(button.style.backgroundColor).not.toBe('transparent');
    });

    it('updates the background color on hover when active (dark mode)', () => {
        setup({ inactive: false, isDark: true });
        const button = screen.getByRole('button', { name: 'Revoke' });
        fireEvent.mouseEnter(button);
        expect(button.style.backgroundColor).not.toBe('transparent');
    });

    it('does not change the background color on hover when inactive', () => {
        setup({ inactive: true });
        const button = screen.getByRole('button', { name: 'Revoke' });
        fireEvent.mouseEnter(button);
        expect(button.style.backgroundColor).toBe('transparent');
    });

    it('resets the background color on mouse leave', () => {
        setup({ inactive: false });
        const button = screen.getByRole('button', { name: 'Revoke' });
        fireEvent.mouseEnter(button);
        fireEvent.mouseLeave(button);
        expect(button.style.backgroundColor).toBe('transparent');
    });

    describe('when pending', () => {
        it('shows the confirmation controls', () => {
            setup({ isPending: true });
            expect(screen.getByText('Revoke?')).toBeInTheDocument();
            expect(screen.getByRole('button', { name: 'Revoke' })).toBeInTheDocument();
            expect(screen.getByRole('button', { name: 'Cancel' })).toBeInTheDocument();
        });

        it('calls onRevoke when confirming', () => {
            const props = setup({ isPending: true });
            fireEvent.click(screen.getByRole('button', { name: 'Revoke' }));
            expect(props.onRevoke).toHaveBeenCalledOnce();
        });

        it('calls onCancel when cancelling', () => {
            const props = setup({ isPending: true });
            fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
            expect(props.onCancel).toHaveBeenCalledOnce();
        });

        it('shows a busy indicator and disables the confirm button while mutating', () => {
            setup({ isPending: true, isMutating: true });
            const button = screen.getByRole('button', { name: '…' });
            expect(button).toBeDisabled();
        });
    });
});
