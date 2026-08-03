import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { NotificationProvider } from '../NotificationProvider';

// NOTE: Despite the name, this component currently does no work beyond
// rendering its children inside a React.Fragment — it wires up no context,
// no toast/notification-bell integration, and no data source (websocket,
// polling, features/notifications). It is also not imported anywhere else
// in the app (no `main.tsx`/`App.tsx` usage), so it is effectively dead
// code today. This is a documented observation, not a fix — scope here is
// coverage-only. Tests below assert the component's actual (trivial)
// current behavior.

describe('NotificationProvider', () => {
    it('renders a single child', () => {
        render(
            <NotificationProvider>
                <div data-testid="child">hello</div>
            </NotificationProvider>
        );

        expect(screen.getByTestId('child')).toBeInTheDocument();
        expect(screen.getByText('hello')).toBeInTheDocument();
    });

    it('renders multiple children', () => {
        render(
            <NotificationProvider>
                <div data-testid="first">first</div>
                <div data-testid="second">second</div>
            </NotificationProvider>
        );

        expect(screen.getByTestId('first')).toBeInTheDocument();
        expect(screen.getByTestId('second')).toBeInTheDocument();
    });

    it('renders nested/text children unchanged', () => {
        render(
            <NotificationProvider>
                <span>
                    outer <strong>inner</strong>
                </span>
            </NotificationProvider>
        );

        expect(screen.getByText('inner')).toBeInTheDocument();
        expect(screen.getByText(/outer/)).toBeInTheDocument();
    });

    it('does not introduce an extra wrapper DOM element', () => {
        const { container } = render(
            <NotificationProvider>
                <div data-testid="only-child" />
            </NotificationProvider>
        );

        // The component returns a Fragment, so the child should be the
        // container's direct/only element with no additional wrapper node.
        expect(container.children).toHaveLength(1);
        expect(container.firstElementChild).toHaveAttribute('data-testid', 'only-child');
    });

    it('renders without children', () => {
        const { container } = render(<NotificationProvider>{null}</NotificationProvider>);

        expect(container).toBeEmptyDOMElement();
    });

    it('renders falsy children gracefully', () => {
        const { container } = render(<NotificationProvider>{false}</NotificationProvider>);

        expect(container).toBeEmptyDOMElement();
    });
});
