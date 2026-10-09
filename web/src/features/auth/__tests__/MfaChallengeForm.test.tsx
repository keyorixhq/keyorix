import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { MfaChallengeForm } from '../MfaChallengeForm';

describe('MfaChallengeForm', () => {
    it('disables Verify until a code is entered', () => {
        render(<MfaChallengeForm onSubmit={vi.fn()} onBack={vi.fn()} />);

        expect(screen.getByTestId('mfa-verify-button')).toBeDisabled();

        fireEvent.change(screen.getByTestId('mfa-code-input'), { target: { value: '123456' } });
        expect(screen.getByTestId('mfa-verify-button')).not.toBeDisabled();
    });

    it('submits the trimmed code', async () => {
        const onSubmit = vi.fn().mockResolvedValue(undefined);
        render(<MfaChallengeForm onSubmit={onSubmit} onBack={vi.fn()} />);

        fireEvent.change(screen.getByTestId('mfa-code-input'), { target: { value: '  123456  ' } });
        fireEvent.click(screen.getByTestId('mfa-verify-button'));

        await waitFor(() => expect(onSubmit).toHaveBeenCalledWith('123456'));
    });

    it('submits a recovery code the same way as a TOTP code', async () => {
        const onSubmit = vi.fn().mockResolvedValue(undefined);
        render(<MfaChallengeForm onSubmit={onSubmit} onBack={vi.fn()} />);

        fireEvent.change(screen.getByTestId('mfa-code-input'), { target: { value: 'ABCD-1234-EFGH' } });
        fireEvent.click(screen.getByTestId('mfa-verify-button'));

        await waitFor(() => expect(onSubmit).toHaveBeenCalledWith('ABCD-1234-EFGH'));
    });

    it('calls onBack when "Back to login" is clicked', () => {
        const onBack = vi.fn();
        render(<MfaChallengeForm onSubmit={vi.fn()} onBack={onBack} />);

        fireEvent.click(screen.getByText('Back to login'));
        expect(onBack).toHaveBeenCalled();
    });

    it('shows the error message passed in, verbatim (never a more specific guess)', () => {
        render(<MfaChallengeForm onSubmit={vi.fn()} onBack={vi.fn()} error="Invalid or expired code" />);
        expect(screen.getByText('Invalid or expired code')).toBeInTheDocument();
    });

    it('shows a distinct rate-limit message when the API returns one', () => {
        render(<MfaChallengeForm onSubmit={vi.fn()} onBack={vi.fn()} error="Too many attempts. Try again later." />);
        expect(screen.getByText('Too many attempts. Try again later.')).toBeInTheDocument();
    });

    it('disables the code input, Verify, and Back while loading', () => {
        render(<MfaChallengeForm onSubmit={vi.fn()} onBack={vi.fn()} isLoading />);

        expect(screen.getByTestId('mfa-code-input')).toBeDisabled();
        expect(screen.getByTestId('mfa-verify-button')).toBeDisabled();
        expect(screen.getByText('Back to login')).toBeDisabled();
    });

    it('renders no error alert when none is passed', () => {
        render(<MfaChallengeForm onSubmit={vi.fn()} onBack={vi.fn()} />);
        expect(screen.queryByText('Invalid or expired code')).not.toBeInTheDocument();
    });
});
