import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { Dialog } from '../Dialog';

describe('Dialog', () => {
    it('renders nothing when isOpen is false', () => {
        render(<Dialog isOpen={false} onClose={vi.fn()} title="Delete item" message="Are you sure?" />);
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });

    it('renders title and message when isOpen is true', () => {
        render(<Dialog isOpen title="Delete item" message="Are you sure you want to delete this?" onClose={vi.fn()} />);
        expect(screen.getByRole('dialog')).toBeInTheDocument();
        expect(screen.getByText('Delete item')).toBeInTheDocument();
        expect(screen.getByText('Are you sure you want to delete this?')).toBeInTheDocument();
    });

    it('renders default confirm/cancel button labels', () => {
        render(<Dialog isOpen title="Confirm" message="Proceed?" onClose={vi.fn()} />);
        expect(screen.getByRole('button', { name: 'OK' })).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Cancel' })).toBeInTheDocument();
    });

    it('renders custom confirm/cancel button labels', () => {
        render(
            <Dialog
                isOpen
                title="Confirm"
                message="Proceed?"
                onClose={vi.fn()}
                confirmText="Delete"
                cancelText="Keep it"
            />
        );
        expect(screen.getByRole('button', { name: 'Delete' })).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Keep it' })).toBeInTheDocument();
    });

    it('hides the cancel button when showCancel is false', () => {
        render(<Dialog isOpen title="Confirm" message="Proceed?" onClose={vi.fn()} showCancel={false} />);
        expect(screen.getByRole('button', { name: 'OK' })).toBeInTheDocument();
        expect(screen.queryByRole('button', { name: 'Cancel' })).not.toBeInTheDocument();
    });

    it('calls onConfirm (not onClose) when confirm is clicked and onConfirm is provided', () => {
        const onConfirm = vi.fn();
        const onClose = vi.fn();
        render(<Dialog isOpen title="Confirm" message="Proceed?" onClose={onClose} onConfirm={onConfirm} />);
        fireEvent.click(screen.getByRole('button', { name: 'OK' }));
        expect(onConfirm).toHaveBeenCalledOnce();
        expect(onClose).not.toHaveBeenCalled();
    });

    it('falls back to onClose when confirm is clicked and no onConfirm is provided', () => {
        const onClose = vi.fn();
        render(<Dialog isOpen title="Confirm" message="Proceed?" onClose={onClose} />);
        fireEvent.click(screen.getByRole('button', { name: 'OK' }));
        expect(onClose).toHaveBeenCalledOnce();
    });

    it('calls onCancel (not onClose) when cancel is clicked and onCancel is provided', () => {
        const onCancel = vi.fn();
        const onClose = vi.fn();
        render(<Dialog isOpen title="Confirm" message="Proceed?" onClose={onClose} onCancel={onCancel} />);
        fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
        expect(onCancel).toHaveBeenCalledOnce();
        expect(onClose).not.toHaveBeenCalled();
    });

    it('falls back to onClose when cancel is clicked and no onCancel is provided', () => {
        const onClose = vi.fn();
        render(<Dialog isOpen title="Confirm" message="Proceed?" onClose={onClose} />);
        fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
        expect(onClose).toHaveBeenCalledOnce();
    });

    // Note: this fires onClose twice, not once. The underlying Modal wires both an
    // explicit `onEscapeKeyDown={() => onClose()}` handler on radix's Dialog.Content
    // AND passes `onOpenChange` to Dialog.Root, and radix's default Escape handling
    // also flips `open` to false there, invoking onClose a second time. That
    // duplicate-invocation quirk lives in Modal.tsx (out of scope for this
    // coverage-only PR on Dialog.tsx), so this test pins the actual observed
    // behavior rather than the single-call behavior one might expect.
    it('calls onClose on Escape key (delegated to the underlying Modal/radix Dialog)', () => {
        const onClose = vi.fn();
        render(<Dialog isOpen title="Confirm" message="Proceed?" onClose={onClose} />);
        fireEvent.keyDown(screen.getByRole('dialog'), { key: 'Escape', code: 'Escape' });
        expect(onClose).toHaveBeenCalledTimes(2);
    });

    it('disables the cancel button and shows a loading state on confirm while loading', () => {
        render(<Dialog isOpen title="Confirm" message="Proceed?" onClose={vi.fn()} loading />);
        expect(screen.getByRole('button', { name: 'Cancel' })).toBeDisabled();
        expect(screen.getByRole('button', { name: 'OK' })).toBeDisabled();
    });

    it('uses the destructive button variant for the danger type', () => {
        render(<Dialog isOpen title="Delete" message="This cannot be undone." onClose={vi.fn()} type="danger" />);
        expect(screen.getByRole('button', { name: 'OK' })).toHaveAttribute('data-variant', 'destructive');
    });

    it.each([['info'], ['warning'], ['success']] as const)(
        'uses the default button variant for the %s type',
        (type) => {
            render(<Dialog isOpen title="Notice" message="Something happened." onClose={vi.fn()} type={type} />);
            expect(screen.getByRole('button', { name: 'OK' })).toHaveAttribute('data-variant', 'default');
        }
    );

    it('renders all four type variants without error', () => {
        const { rerender } = render(<Dialog isOpen title="T" message="M" onClose={vi.fn()} type="info" />);
        rerender(<Dialog isOpen title="T" message="M" onClose={vi.fn()} type="warning" />);
        rerender(<Dialog isOpen title="T" message="M" onClose={vi.fn()} type="success" />);
        rerender(<Dialog isOpen title="T" message="M" onClose={vi.fn()} type="danger" />);
        expect(screen.getByRole('dialog')).toBeInTheDocument();
    });

    // Bug (documented, not fixed per coverage-only PR scope): Dialog renders its own
    // plain <h3> for `title` instead of passing `title` through to the underlying
    // <Modal>. Because Modal's `title` prop is never set (and showCloseButton is
    // forced to false), Modal never renders a radix `Dialog.Title`, so the dialog
    // has no accessible name/title for screen readers — radix logs a console error
    // ("`DialogContent` requires a `DialogTitle`") for every open Dialog. This test
    // pins down that observable symptom without attempting a fix.
    it('does not wire an accessible radix Dialog.Title (known a11y gap - see comment above)', () => {
        render(<Dialog isOpen title="Delete item" message="Are you sure?" onClose={vi.fn()} />);
        expect(screen.getByRole('dialog')).not.toHaveAccessibleName();
    });
});
