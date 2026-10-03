import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { MfaChallengeForm } from '../MfaChallengeForm';

describe('MfaChallengeForm', () => {
    it('shows a validation error and does not submit when the code is empty', async () => {
        const onSubmit = vi.fn();
        render(<MfaChallengeForm onSubmit={onSubmit} onBack={vi.fn()} />);

        fireEvent.click(screen.getByTestId('mfa-verify-button'));

        expect(await screen.findByText('Enter your authenticator code or a recovery code')).toBeInTheDocument();
        expect(onSubmit).not.toHaveBeenCalled();
    });

    it('submits a 6-digit TOTP code', async () => {
        const onSubmit = vi.fn().mockResolvedValue(undefined);
        render(<MfaChallengeForm onSubmit={onSubmit} onBack={vi.fn()} />);

        fireEvent.change(screen.getByTestId('mfa-code-input'), { target: { value: '123456' } });
        fireEvent.click(screen.getByTestId('mfa-verify-button'));

        await waitFor(() => expect(onSubmit).toHaveBeenCalledWith('123456'));
    });

    // #2442's VerifyMFA accepts a recovery code in the same field as a TOTP
    // code (server-side, not something the client needs to distinguish) --
    // this form must not reject recovery-code-shaped input client-side.
    it('submits a recovery code just as readily as a TOTP code', async () => {
        const onSubmit = vi.fn().mockResolvedValue(undefined);
        render(<MfaChallengeForm onSubmit={onSubmit} onBack={vi.fn()} />);

        fireEvent.change(screen.getByTestId('mfa-code-input'), { target: { value: 'ABCDE-12345' } });
        fireEvent.click(screen.getByTestId('mfa-verify-button'));

        await waitFor(() => expect(onSubmit).toHaveBeenCalledWith('ABCDE-12345'));
    });

    it('calls onBack when "Back to sign in" is clicked', () => {
        const onBack = vi.fn();
        render(<MfaChallengeForm onSubmit={vi.fn()} onBack={onBack} />);

        fireEvent.click(screen.getByText('Back to sign in'));
        expect(onBack).toHaveBeenCalled();
    });

    it('shows the server error message when provided', () => {
        render(<MfaChallengeForm onSubmit={vi.fn()} onBack={vi.fn()} error="Invalid or expired code" />);
        expect(screen.getByText('Invalid or expired code')).toBeInTheDocument();
    });

    it('disables the input, verify button, and back link while isLoading', () => {
        render(<MfaChallengeForm onSubmit={vi.fn()} onBack={vi.fn()} isLoading />);

        expect(screen.getByTestId('mfa-code-input')).toBeDisabled();
        expect(screen.getByTestId('mfa-verify-button')).toBeDisabled();
        expect(screen.getByText('Back to sign in')).toBeDisabled();
    });
});
