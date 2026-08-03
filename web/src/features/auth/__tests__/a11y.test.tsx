import React from 'react';
import { render } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { axe } from 'jest-axe';
import { LoginForm } from '../LoginForm';
import { PasswordResetForm } from '../PasswordResetForm';
import { SetupForm } from '../SetupForm';

const a11y = (element: Element) => axe(element, { rules: { 'color-contrast': { enabled: false } } });

// ── LoginForm ─────────────────────────────────────────────────────────────────

describe('LoginForm a11y', () => {
    it('idle state has no violations', async () => {
        const { container } = render(<LoginForm onSubmit={vi.fn()} />);
        expect(await a11y(container)).toHaveNoViolations();
    });

    it('server-side error state has no violations', async () => {
        const { container } = render(<LoginForm onSubmit={vi.fn()} error="Invalid username or password" />);
        expect(await a11y(container)).toHaveNoViolations();
    });

    it('loading state has no violations', async () => {
        const { container } = render(<LoginForm onSubmit={vi.fn()} isLoading />);
        expect(await a11y(container)).toHaveNoViolations();
    });

    it('with forgot-password callback has no violations', async () => {
        const { container } = render(<LoginForm onSubmit={vi.fn()} onForgotPassword={vi.fn()} />);
        expect(await a11y(container)).toHaveNoViolations();
    });
});

// ── PasswordResetForm ─────────────────────────────────────────────────────────

describe('PasswordResetForm a11y', () => {
    it('idle state has no violations', async () => {
        const { container } = render(<PasswordResetForm onSubmit={vi.fn()} onBack={vi.fn()} />);
        expect(await a11y(container)).toHaveNoViolations();
    });

    it('server-side error state has no violations', async () => {
        const { container } = render(
            <PasswordResetForm onSubmit={vi.fn()} onBack={vi.fn()} error="No account with that email" />
        );
        expect(await a11y(container)).toHaveNoViolations();
    });

    it('success state has no violations', async () => {
        const { container } = render(<PasswordResetForm onSubmit={vi.fn()} onBack={vi.fn()} success />);
        expect(await a11y(container)).toHaveNoViolations();
    });
});

// ── SetupForm ─────────────────────────────────────────────────────────────────

describe('SetupForm a11y', () => {
    it('idle state has no violations', async () => {
        const { container } = render(<SetupForm onSubmit={vi.fn()} />);
        expect(await a11y(container)).toHaveNoViolations();
    });

    it('server-side error state has no violations', async () => {
        const { container } = render(<SetupForm onSubmit={vi.fn()} error="Token has expired" />);
        expect(await a11y(container)).toHaveNoViolations();
    });

    it('loading state has no violations', async () => {
        const { container } = render(<SetupForm onSubmit={vi.fn()} isLoading />);
        expect(await a11y(container)).toHaveNoViolations();
    });
});
