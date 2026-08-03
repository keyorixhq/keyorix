import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { SetupForm } from '../SetupForm';

describe('SetupForm', () => {
    it('shows a validation error and does not submit when the password is empty', async () => {
        const onSubmit = vi.fn();
        render(<SetupForm onSubmit={onSubmit} />);

        fireEvent.click(screen.getByRole('button', { name: /set password and continue/i }));

        expect(await screen.findByText('Password is required')).toBeInTheDocument();
        expect(onSubmit).not.toHaveBeenCalled();
    });

    it('submits the new password once both fields match', async () => {
        const onSubmit = vi.fn().mockResolvedValue(undefined);
        render(<SetupForm onSubmit={onSubmit} />);

        fireEvent.change(screen.getByLabelText('New password'), { target: { value: 'Str0ng!Passw0rd' } });
        fireEvent.change(screen.getByLabelText('Confirm password'), { target: { value: 'Str0ng!Passw0rd' } });
        fireEvent.click(screen.getByRole('button', { name: /set password and continue/i }));

        await waitFor(() => expect(onSubmit).toHaveBeenCalledWith('Str0ng!Passw0rd'));
    });

    it('toggles visibility, aria-label, and the reveal icon for both password fields', () => {
        render(<SetupForm onSubmit={vi.fn()} />);

        const newPassword = screen.getByLabelText('New password');
        const confirmPassword = screen.getByLabelText('Confirm password');
        expect(newPassword).toHaveAttribute('type', 'password');
        expect(confirmPassword).toHaveAttribute('type', 'password');

        fireEvent.click(screen.getByRole('button', { name: 'Show password' }));
        expect(newPassword).toHaveAttribute('type', 'text');
        expect(confirmPassword).toHaveAttribute('type', 'text');
        expect(screen.getByRole('button', { name: 'Hide password' })).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Hide password' }));
        expect(newPassword).toHaveAttribute('type', 'password');
        expect(confirmPassword).toHaveAttribute('type', 'password');
        expect(screen.getByRole('button', { name: 'Show password' })).toBeInTheDocument();
    });
});
