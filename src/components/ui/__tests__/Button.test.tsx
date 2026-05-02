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

    it('applies primary variant styles', () => {
        render(<Button variant="primary">Primary</Button>);
        expect(screen.getByRole('button')).toHaveClass('bg-blue-600');
    });

    it('applies danger variant styles', () => {
        render(<Button variant="danger">Danger</Button>);
        expect(screen.getByRole('button')).toHaveClass('bg-red-600');
    });

    it('can be disabled', () => {
        render(<Button disabled>Disabled</Button>);
        expect(screen.getByRole('button')).toBeDisabled();
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
});
