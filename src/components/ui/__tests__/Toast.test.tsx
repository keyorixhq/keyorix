import { describe, it, expect, vi, afterEach } from 'vitest';
import { act, render, screen, fireEvent, waitFor } from '@testing-library/react';
import { ToastComponent, ToastContainer } from '../Toast';
import type { Toast } from '../Toast';

afterEach(() => {
    vi.useRealTimers();
});

describe('ToastComponent', () => {
    it('renders the title and message', () => {
        render(<ToastComponent id="1" type="info" title="Heads up" message="Something happened" onClose={vi.fn()} />);
        expect(screen.getByText('Heads up')).toBeInTheDocument();
        expect(screen.getByText('Something happened')).toBeInTheDocument();
    });

    it('renders without a message paragraph when none is provided', () => {
        render(<ToastComponent id="1" type="info" title="Heads up" onClose={vi.fn()} />);
        expect(screen.getByText('Heads up')).toBeInTheDocument();
        expect(screen.queryByText('Something happened')).not.toBeInTheDocument();
    });

    it.each([
        ['success', 'var(--success)', 'var(--success-subtle)'],
        ['error', 'var(--error)', 'var(--error-subtle)'],
        ['warning', 'var(--warning)', 'var(--warning-subtle)'],
        ['info', 'var(--accent)', 'var(--accent-subtle)'],
    ] as const)('applies the %s variant colors and an icon', (type, iconColor, bg) => {
        const { container } = render(<ToastComponent id="1" type={type} title="t" onClose={vi.fn()} />);
        const root = container.firstChild as HTMLElement;
        expect(root.style.borderColor).toBe(iconColor);
        expect(root.style.backgroundColor).toBe(bg);
        expect(container.querySelector('svg[aria-hidden="true"]')).toBeInTheDocument();
    });

    it('flips from the entering state to the visible state after mount', async () => {
        const { container } = render(<ToastComponent id="1" type="info" title="t" onClose={vi.fn()} />);
        const root = container.firstChild as HTMLElement;
        expect(root.className).toContain('opacity-0');

        await waitFor(() => expect(root.className).toContain('opacity-100'));
    });

    it('calls onClose with the toast id after the close button is clicked and the leave animation completes', async () => {
        vi.useFakeTimers();
        const onClose = vi.fn();
        render(<ToastComponent id="abc" type="info" title="t" onClose={onClose} />);
        const btn = screen.getByRole('button', { name: /close/i });

        await act(async () => {
            fireEvent.click(btn);
        });
        expect(onClose).not.toHaveBeenCalled();

        await act(async () => {
            await vi.advanceTimersByTimeAsync(200);
        });
        expect(onClose).toHaveBeenCalledWith('abc');
    });

    it('auto-dismisses after the given duration plus the leave animation', async () => {
        vi.useFakeTimers();
        const onClose = vi.fn();
        render(<ToastComponent id="xyz" type="success" title="t" duration={1000} onClose={onClose} />);

        await act(async () => {
            await vi.advanceTimersByTimeAsync(999);
        });
        expect(onClose).not.toHaveBeenCalled();

        await act(async () => {
            await vi.advanceTimersByTimeAsync(1);
        });
        // duration has now elapsed: the toast starts its leave animation but onClose
        // only fires once the leave animation (LEAVE_MS) also completes.
        expect(onClose).not.toHaveBeenCalled();

        await act(async () => {
            await vi.advanceTimersByTimeAsync(200);
        });
        expect(onClose).toHaveBeenCalledWith('xyz');
    });

    it('does not auto-dismiss when persistent is true', async () => {
        vi.useFakeTimers();
        const onClose = vi.fn();
        render(<ToastComponent id="p1" type="warning" title="t" duration={100} persistent onClose={onClose} />);

        await act(async () => {
            await vi.advanceTimersByTimeAsync(100000);
        });
        expect(onClose).not.toHaveBeenCalled();
    });

    it('does not auto-dismiss when duration is 0', async () => {
        vi.useFakeTimers();
        const onClose = vi.fn();
        render(<ToastComponent id="d0" type="error" title="t" duration={0} onClose={onClose} />);

        await act(async () => {
            await vi.advanceTimersByTimeAsync(100000);
        });
        expect(onClose).not.toHaveBeenCalled();
    });

    it('clears the pending auto-dismiss timer on unmount so onClose never fires', async () => {
        vi.useFakeTimers();
        const onClose = vi.fn();
        const { unmount } = render(<ToastComponent id="u1" type="info" title="t" duration={500} onClose={onClose} />);

        unmount();

        await act(async () => {
            await vi.advanceTimersByTimeAsync(10000);
        });
        expect(onClose).not.toHaveBeenCalled();
    });
});

describe('ToastContainer', () => {
    const toasts: Toast[] = [
        { id: '1', type: 'success', title: 'First' },
        { id: '2', type: 'error', title: 'Second' },
    ];

    it('renders no toast items when the list is empty', () => {
        render(<ToastContainer toasts={[]} onClose={vi.fn()} />);
        expect(screen.queryByText('First')).not.toBeInTheDocument();
    });

    it('renders every toast in the list, stacked', () => {
        render(<ToastContainer toasts={toasts} onClose={vi.fn()} />);
        expect(screen.getByText('First')).toBeInTheDocument();
        expect(screen.getByText('Second')).toBeInTheDocument();
    });

    it('marks the region as an assertive live region for screen readers', () => {
        const { container } = render(<ToastContainer toasts={toasts} onClose={vi.fn()} />);
        expect(container.querySelector('[aria-live="assertive"]')).toBeInTheDocument();
    });

    it('defaults to the top-right position', () => {
        const { container } = render(<ToastContainer toasts={[]} onClose={vi.fn()} />);
        const region = container.querySelector('[aria-live="assertive"]') as HTMLElement;
        expect(region.className).toContain('top-0');
        expect(region.className).toContain('right-0');
    });

    it('applies the requested position classes', () => {
        const { container } = render(<ToastContainer toasts={[]} onClose={vi.fn()} position="bottom-center" />);
        const region = container.querySelector('[aria-live="assertive"]') as HTMLElement;
        expect(region.className).toContain('bottom-0');
        expect(region.className).toContain('left-1/2');
    });

    it('forwards onClose with the correct id when a specific toast is dismissed', async () => {
        vi.useFakeTimers();
        const onClose = vi.fn();
        render(<ToastContainer toasts={toasts} onClose={onClose} />);

        const closeButtons = screen.getAllByRole('button', { name: /close/i });
        expect(closeButtons).toHaveLength(2);

        await act(async () => {
            fireEvent.click(closeButtons[1]);
        });
        await act(async () => {
            await vi.advanceTimersByTimeAsync(200);
        });
        expect(onClose).toHaveBeenCalledWith('2');
        expect(onClose).not.toHaveBeenCalledWith('1');
    });
});
