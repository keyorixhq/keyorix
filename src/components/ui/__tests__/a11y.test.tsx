import React from 'react';
import { render } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { axe } from 'jest-axe';
import { Button } from '../Button';
import { Input } from '../Input';
import { Alert } from '../Alert';

// jsdom has no CSS engine, so color-contrast can never be verified here.
const a11y = (element: Element) => axe(element, { rules: { 'color-contrast': { enabled: false } } });

// ── Button ────────────────────────────────────────────────────────────────────

describe('Button a11y', () => {
    it('default variant has no violations', async () => {
        const { container } = render(<Button>Submit</Button>);
        expect(await a11y(container)).toHaveNoViolations();
    });

    it('secondary variant has no violations', async () => {
        const { container } = render(<Button variant="secondary">Cancel</Button>);
        expect(await a11y(container)).toHaveNoViolations();
    });

    it('outline variant has no violations', async () => {
        const { container } = render(<Button variant="outline">More</Button>);
        expect(await a11y(container)).toHaveNoViolations();
    });

    it('destructive variant has no violations', async () => {
        const { container } = render(<Button variant="destructive">Delete</Button>);
        expect(await a11y(container)).toHaveNoViolations();
    });

    it('disabled state has no violations', async () => {
        const { container } = render(<Button disabled>Submit</Button>);
        expect(await a11y(container)).toHaveNoViolations();
    });

    it('loading state has no violations', async () => {
        const { container } = render(<Button loading>Saving…</Button>);
        expect(await a11y(container)).toHaveNoViolations();
    });
});

// ── Input ─────────────────────────────────────────────────────────────────────

describe('Input a11y', () => {
    it('labeled input has no violations', async () => {
        const { container } = render(<Input label="Email address" type="email" />);
        expect(await a11y(container)).toHaveNoViolations();
    });

    it('error state exposes aria-invalid and describedby without violations', async () => {
        const { container } = render(
            <Input label="Email address" type="email" error="Enter a valid email" />
        );
        expect(await a11y(container)).toHaveNoViolations();
    });

    it('helper-text state has no violations', async () => {
        const { container } = render(
            <Input label="Password" type="password" helperText="At least 8 characters" />
        );
        expect(await a11y(container)).toHaveNoViolations();
    });

    it('aria-label replaces visible label without violations', async () => {
        const { container } = render(<Input aria-label="Search" type="search" />);
        expect(await a11y(container)).toHaveNoViolations();
    });

    it('disabled state has no violations', async () => {
        const { container } = render(<Input label="Username" disabled />);
        expect(await a11y(container)).toHaveNoViolations();
    });
});

// ── Alert ─────────────────────────────────────────────────────────────────────

describe('Alert a11y', () => {
    it('success type has no violations', async () => {
        const { container } = render(<Alert type="success" title="Saved" message="Your changes were saved." />);
        expect(await a11y(container)).toHaveNoViolations();
    });

    it('error type has no violations', async () => {
        const { container } = render(<Alert type="error" title="Error" message="Something went wrong." />);
        expect(await a11y(container)).toHaveNoViolations();
    });

    it('warning type has no violations', async () => {
        const { container } = render(<Alert type="warning" message="Please review before continuing." />);
        expect(await a11y(container)).toHaveNoViolations();
    });

    it('info type has no violations', async () => {
        const { container } = render(<Alert type="info" message="Just so you know." />);
        expect(await a11y(container)).toHaveNoViolations();
    });

    it('dismissible alert has an accessible dismiss button', async () => {
        const { container } = render(<Alert type="info" title="Notice" dismissible onDismiss={vi.fn()} />);
        expect(await a11y(container)).toHaveNoViolations();
    });

    it('alert with only children has no violations', async () => {
        const { container } = render(
            <Alert type="warning">
                <strong>Action required:</strong> please update your password.
            </Alert>
        );
        expect(await a11y(container)).toHaveNoViolations();
    });
});
