import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { Alert, AlertList } from '../Alert';

describe('Alert', () => {
    it('renders a title and message', () => {
        render(<Alert type="success" title="Done" message="Operation completed." />);
        expect(screen.getByText('Done')).toBeInTheDocument();
        expect(screen.getByText('Operation completed.')).toBeInTheDocument();
    });

    it('renders children as body content', () => {
        render(
            <Alert type="info">
                <span>Custom body</span>
            </Alert>
        );
        expect(screen.getByText('Custom body')).toBeInTheDocument();
    });

    it('renders all four types without error', () => {
        const { rerender } = render(<Alert type="success" title="ok" />);
        rerender(<Alert type="error" title="ok" />);
        rerender(<Alert type="warning" title="ok" />);
        rerender(<Alert type="info" title="ok" />);
        expect(screen.getByText('ok')).toBeInTheDocument();
    });

    it('shows a dismiss button when dismissible and onDismiss provided', () => {
        const onDismiss = vi.fn();
        render(<Alert type="error" title="Oops" dismissible onDismiss={onDismiss} />);
        const btn = screen.getByRole('button', { name: /dismiss/i });
        fireEvent.click(btn);
        expect(onDismiss).toHaveBeenCalledOnce();
    });

    it('does not show dismiss button when dismissible but no onDismiss', () => {
        render(<Alert type="warning" title="Watch out" dismissible />);
        expect(screen.queryByRole('button', { name: /dismiss/i })).not.toBeInTheDocument();
    });
});

describe('AlertList', () => {
    it('renders nothing when alerts array is empty', () => {
        const { container } = render(<AlertList alerts={[]} />);
        expect(container.firstChild).toBeNull();
    });

    it('renders each alert and calls onDismiss with the right id', () => {
        const onDismiss = vi.fn();
        const alerts = [
            { id: 'a1', type: 'success' as const, title: 'A', dismissible: true },
            { id: 'a2', type: 'error' as const, title: 'B', dismissible: true },
        ];
        render(<AlertList alerts={alerts} onDismiss={onDismiss} />);
        expect(screen.getByText('A')).toBeInTheDocument();
        expect(screen.getByText('B')).toBeInTheDocument();

        const [firstBtn] = screen.getAllByRole('button', { name: /dismiss/i });
        fireEvent.click(firstBtn);
        expect(onDismiss).toHaveBeenCalledWith('a1');
    });
});
