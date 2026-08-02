import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { Button } from '../Button';

describe('Button', () => {
    it('renders with text', () => {
        render(<Button>Click me</Button>);
        expect(screen.getByRole('button', { name: 'Click me' })).toBeInTheDocument();
    });

    it('handles click events', () => {
        const handleClick = vi.fn();
        render(<Button onClick={handleClick}>Click me</Button>);
        fireEvent.click(screen.getByRole('button'));
        expect(handleClick).toHaveBeenCalledTimes(1);
    });

    it('applies default variant styles', () => {
        render(<Button variant="default">Default</Button>);
        expect(screen.getByRole('button')).toHaveClass('bg-primary');
    });

    it('applies destructive variant styles', () => {
        render(<Button variant="destructive">Destructive</Button>);
        expect(screen.getByRole('button')).toHaveClass('bg-destructive');
    });

    it('can be disabled', () => {
        render(<Button disabled>Disabled</Button>);
        expect(screen.getByRole('button')).toBeDisabled();
    });

    it('disables the button and renders a spinner while loading', () => {
        render(<Button loading>Save</Button>);
        const button = screen.getByRole('button');
        expect(button).toBeDisabled();
        expect(button.querySelector('svg.animate-spin')).toBeInTheDocument();
    });

    it('forwards refs correctly', () => {
        const ref = React.createRef<HTMLButtonElement>();
        render(<Button ref={ref}>Button</Button>);
        expect(ref.current).toBeInstanceOf(HTMLButtonElement);
    });

    it('supports custom className', () => {
        render(<Button className="custom-class">Custom</Button>);
        expect(screen.getByRole('button')).toHaveClass('custom-class');
    });

    // BUG (documented, not fixed per task scope): Button always renders
    // `{loading && (<svg .../>)}` as a sibling of `children`. When `asChild` is
    // true that pair is passed straight through as the children of Radix's
    // `Slot.Root`, which requires `React.Children.count(children) === 1` to
    // accept a single slotted element. `Children.count` (unlike
    // `Children.toArray`) does NOT filter out boolean children, so the count
    // is always 2 (the `false`/`<svg>` plus the real child) and Slot throws -
    // `asChild` is therefore unusable on Button as currently written. This is
    // not user-visible today because no call site in the app passes asChild.
    it('throws when asChild is used, because the conditional spinner leaves an extra boolean child for Slot', () => {
        const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
        expect(() =>
            render(
                <Button asChild>
                    <a href="/foo">Link button</a>
                </Button>
            )
        ).toThrow(/Slot/);
        consoleErrorSpy.mockRestore();
    });
});
