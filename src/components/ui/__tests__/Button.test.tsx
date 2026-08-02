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

    it('renders as its child element via asChild instead of a <button>', () => {
        render(
            <Button asChild>
                <a href="/somewhere">Go</a>
            </Button>
        );
        const link = screen.getByRole('link', { name: 'Go' });
        expect(link).toBeInTheDocument();
        expect(link.tagName).toBe('A');
        expect(link).toHaveClass('bg-primary');
    });

    it('does not throw when asChild is combined with loading', () => {
        expect(() =>
            render(
                <Button asChild loading>
                    <a href="/somewhere">Go</a>
                </Button>
            )
        ).not.toThrow();
        expect(screen.getByRole('link', { name: 'Go' })).toBeInTheDocument();
    });
});
