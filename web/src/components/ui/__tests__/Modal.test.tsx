import React from 'react';
import { describe, it, expect, vi, afterEach } from 'vitest';
import { act, render, screen, fireEvent } from '@testing-library/react';
import { Modal } from '../Modal';

afterEach(() => {
    vi.useRealTimers();
});

describe('Modal', () => {
    it('renders nothing visible when isOpen is false', () => {
        render(
            <Modal isOpen={false} onClose={vi.fn()} title="Details">
                <p>Body</p>
            </Modal>
        );
        expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });

    it('renders the title, close button, and children when open', () => {
        render(
            <Modal isOpen onClose={vi.fn()} title="Details">
                <p>Body content</p>
            </Modal>
        );
        expect(screen.getByRole('dialog')).toBeInTheDocument();
        expect(screen.getByText('Details')).toBeInTheDocument();
        expect(screen.getByText('Body content')).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Close' })).toBeInTheDocument();
    });

    it('hides the close button when showCloseButton is false', () => {
        render(
            <Modal isOpen onClose={vi.fn()} title="Details" showCloseButton={false}>
                <p>Body</p>
            </Modal>
        );
        expect(screen.queryByRole('button', { name: 'Close' })).not.toBeInTheDocument();
    });

    it('hides the header entirely when there is no title and no close button', () => {
        render(
            <Modal isOpen onClose={vi.fn()} showCloseButton={false}>
                <p>Body</p>
            </Modal>
        );
        expect(screen.queryByRole('button', { name: 'Close' })).not.toBeInTheDocument();
        expect(screen.queryByText('Details')).not.toBeInTheDocument();
    });

    it('renders the title visually hidden when hideTitleVisually is true, keeping it as the accessible name', () => {
        render(
            <Modal isOpen onClose={vi.fn()} title="Details" hideTitleVisually>
                <p>Body</p>
            </Modal>
        );
        expect(screen.getByRole('dialog')).toHaveAccessibleName('Details');
        expect(screen.getByText('Details')).toHaveClass('sr-only');
    });

    it('calls onClose when the close button is clicked', () => {
        const onClose = vi.fn();
        render(
            <Modal isOpen onClose={onClose} title="Details">
                <p>Body</p>
            </Modal>
        );
        fireEvent.click(screen.getByRole('button', { name: 'Close' }));
        expect(onClose).toHaveBeenCalledOnce();
    });

    it('calls onClose on Escape', () => {
        const onClose = vi.fn();
        render(
            <Modal isOpen onClose={onClose} title="Details">
                <p>Body</p>
            </Modal>
        );
        fireEvent.keyDown(screen.getByRole('dialog'), { key: 'Escape', code: 'Escape' });
        expect(onClose).toHaveBeenCalledTimes(1);
    });

    it('still renders normally when closeOnOverlayClick is false', () => {
        const onClose = vi.fn();
        render(
            <Modal isOpen onClose={onClose} title="Details" closeOnOverlayClick={false}>
                <p>Body</p>
            </Modal>
        );
        expect(screen.getByRole('dialog')).toBeInTheDocument();
    });

    it('does not close when the overlay is clicked and closeOnOverlayClick is false', () => {
        const onClose = vi.fn();
        const { baseElement } = render(
            <Modal isOpen onClose={onClose} title="Details" closeOnOverlayClick={false}>
                <p>Body</p>
            </Modal>
        );
        const overlay = baseElement.querySelector('.bg-black\\/40') as HTMLElement;
        fireEvent.pointerDown(overlay);
        fireEvent.click(overlay);
        expect(onClose).not.toHaveBeenCalled();
        expect(screen.getByRole('dialog')).toBeInTheDocument();
    });

    it("suppresses the outside-interaction dismiss once Radix's dismissable layer actually processes it when closeOnOverlayClick is false", async () => {
        // Radix's DismissableLayer defers attaching its document-level "outside
        // pointerdown" listener by a setTimeout(0) (to avoid reacting to the same
        // interaction that opened the dialog), and with a modal Dialog.Content the
        // pointerdown-outside dismissal itself is deferred again until the
        // following click. Both hops need real elapsed time to run, so fake timers
        // + a full pointerdown-then-click sequence are required to actually reach
        // Modal's onInteractOutside handler (it never fires on a synchronous
        // fireEvent in the same tick as render).
        vi.useFakeTimers();
        const onClose = vi.fn();
        const { baseElement } = render(
            <Modal isOpen onClose={onClose} title="Details" closeOnOverlayClick={false}>
                <p>Body</p>
            </Modal>
        );
        await act(async () => {
            await vi.advanceTimersByTimeAsync(0);
        });
        const overlay = baseElement.querySelector('.bg-black\\/40') as HTMLElement;
        fireEvent.pointerDown(overlay, { button: 0 });
        fireEvent.click(overlay);
        await act(async () => {
            await vi.advanceTimersByTimeAsync(0);
        });
        expect(onClose).not.toHaveBeenCalled();
        expect(screen.getByRole('dialog')).toBeInTheDocument();
    });

    it.each([['sm'], ['md'], ['lg'], ['xl'], ['full']] as const)('renders the %s size without error', (size) => {
        render(
            <Modal isOpen onClose={vi.fn()} title="Details" size={size}>
                <p>Body</p>
            </Modal>
        );
        expect(screen.getByRole('dialog')).toBeInTheDocument();
    });

    it('applies a custom className to the content panel', () => {
        render(
            <Modal isOpen onClose={vi.fn()} title="Details" className="custom-modal">
                <p>Body</p>
            </Modal>
        );
        expect(screen.getByRole('dialog')).toHaveClass('custom-modal');
    });
});
