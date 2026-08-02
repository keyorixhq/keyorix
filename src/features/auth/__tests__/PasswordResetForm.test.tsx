import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { PasswordResetForm } from '../PasswordResetForm';

describe('PasswordResetForm', () => {
    it('shows a validation error and does not submit when the email is empty', async () => {
        const onSubmit = vi.fn();
        render(<PasswordResetForm onSubmit={onSubmit} onBack={vi.fn()} />);

        fireEvent.click(screen.getByRole('button', { name: 'Send Reset Link' }));

        expect(await screen.findByText('Email is required')).toBeInTheDocument();
        expect(onSubmit).not.toHaveBeenCalled();
    });

    it('submits the entered email once it is valid', async () => {
        const onSubmit = vi.fn().mockResolvedValue(undefined);
        render(<PasswordResetForm onSubmit={onSubmit} onBack={vi.fn()} />);

        fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'dana@acme.io' } });
        fireEvent.click(screen.getByRole('button', { name: 'Send Reset Link' }));

        await waitFor(() => expect(onSubmit).toHaveBeenCalledWith({ email: 'dana@acme.io' }, expect.anything()));
    });

    it('calls onBack when "Back to Login" is clicked', () => {
        const onBack = vi.fn();
        render(<PasswordResetForm onSubmit={vi.fn()} onBack={onBack} />);

        fireEvent.click(screen.getByRole('button', { name: 'Back to Login' }));
        expect(onBack).toHaveBeenCalled();
    });
});
