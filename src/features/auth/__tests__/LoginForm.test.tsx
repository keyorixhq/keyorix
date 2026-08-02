import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { LoginForm } from '../LoginForm';

describe('LoginForm', () => {
    it('shows validation errors and does not submit when fields are empty', async () => {
        const onSubmit = vi.fn();
        render(<LoginForm onSubmit={onSubmit} />);

        fireEvent.click(screen.getByTestId('login-button'));

        expect(await screen.findByText('Username is required')).toBeInTheDocument();
        expect(screen.getByText('Password must be at least 6 characters')).toBeInTheDocument();
        expect(onSubmit).not.toHaveBeenCalled();
    });

    it('submits the entered credentials once fields are valid', async () => {
        const onSubmit = vi.fn().mockResolvedValue(undefined);
        render(<LoginForm onSubmit={onSubmit} />);

        fireEvent.change(screen.getByTestId('username-input'), { target: { value: 'dana' } });
        fireEvent.change(screen.getByTestId('password-input'), { target: { value: 'Str0ngPass!' } });
        fireEvent.click(screen.getByTestId('login-button'));

        await waitFor(() =>
            expect(onSubmit).toHaveBeenCalledWith({
                username: 'dana',
                password: 'Str0ngPass!',
                rememberMe: false,
            })
        );
    });

    it('toggles password visibility, aria-label, and the reveal icon', () => {
        render(<LoginForm onSubmit={vi.fn()} />);

        const passwordInput = screen.getByTestId('password-input');
        expect(passwordInput).toHaveAttribute('type', 'password');
        const toggle = screen.getByRole('button', { name: 'Show password' });

        fireEvent.click(toggle);
        expect(passwordInput).toHaveAttribute('type', 'text');
        expect(screen.getByRole('button', { name: 'Hide password' })).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Hide password' }));
        expect(passwordInput).toHaveAttribute('type', 'password');
        expect(screen.getByRole('button', { name: 'Show password' })).toBeInTheDocument();
    });

    it('calls onForgotPassword when the link is clicked', () => {
        const onForgotPassword = vi.fn();
        render(<LoginForm onSubmit={vi.fn()} onForgotPassword={onForgotPassword} />);

        fireEvent.click(screen.getByText('Forgot password?'));
        expect(onForgotPassword).toHaveBeenCalled();
    });
});
