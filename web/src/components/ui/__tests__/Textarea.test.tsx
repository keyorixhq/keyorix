import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { Textarea } from '../Textarea';

describe('Textarea', () => {
    it('renders with a label', () => {
        render(<Textarea label="Description" />);
        expect(screen.getByLabelText('Description')).toBeInTheDocument();
    });

    it('renders without a label', () => {
        render(<Textarea placeholder="No label here" />);
        expect(screen.queryByText('Description')).not.toBeInTheDocument();
        expect(screen.getByPlaceholderText('No label here')).toBeInTheDocument();
    });

    it('handles value changes', () => {
        const handleChange = vi.fn();
        render(<Textarea label="Description" onChange={handleChange} />);
        fireEvent.change(screen.getByLabelText('Description'), { target: { value: 'hello' } });
        expect(handleChange).toHaveBeenCalledOnce();
    });

    it('shows an error message and error styling on the label', () => {
        render(<Textarea label="Description" error="Required" />);
        expect(screen.getByRole('alert')).toHaveTextContent('Required');
        expect(screen.getByText('Description')).toHaveClass('text-red-700');
    });

    it('applies default label styling when there is no error', () => {
        render(<Textarea label="Description" />);
        expect(screen.getByText('Description')).toHaveClass('text-gray-700');
    });

    it('shows helper text when there is no error', () => {
        render(<Textarea label="Description" helperText="Optional details" />);
        expect(screen.getByText('Optional details')).toBeInTheDocument();
    });

    it('hides helper text when an error is present', () => {
        render(<Textarea label="Description" error="Required" helperText="Optional details" />);
        expect(screen.queryByText('Optional details')).not.toBeInTheDocument();
    });

    it('defaults to full width', () => {
        render(<Textarea label="Description" />);
        expect(screen.getByLabelText('Description')).toHaveClass('w-full');
    });

    it('applies auto width when fullWidth is false', () => {
        render(<Textarea label="Description" fullWidth={false} />);
        expect(screen.getByLabelText('Description')).toHaveClass('w-auto');
    });

    it.each([
        ['none', 'resize-none'],
        ['vertical', 'resize-y'],
        ['horizontal', 'resize-x'],
        ['both', 'resize'],
    ] as const)('applies the %s resize class', (resize, resizeClass) => {
        render(<Textarea label="Description" resize={resize} />);
        expect(screen.getByLabelText('Description')).toHaveClass(resizeClass);
    });

    it('defaults to 3 rows', () => {
        render(<Textarea label="Description" />);
        expect(screen.getByLabelText('Description')).toHaveAttribute('rows', '3');
    });

    it('can be disabled', () => {
        render(<Textarea label="Description" disabled />);
        expect(screen.getByLabelText('Description')).toBeDisabled();
    });

    it('forwards refs', () => {
        const ref = React.createRef<HTMLTextAreaElement>();
        render(<Textarea ref={ref} label="Description" />);
        expect(ref.current).toBeInstanceOf(HTMLTextAreaElement);
    });

    it('generates an id when none is provided', () => {
        render(<Textarea label="Description" />);
        expect(screen.getByLabelText('Description')).toHaveAttribute('id');
    });

    it('uses a provided id instead of generating one', () => {
        render(<Textarea label="Description" id="my-textarea" />);
        expect(screen.getByLabelText('Description')).toHaveAttribute('id', 'my-textarea');
    });

    it('supports a custom className', () => {
        render(<Textarea label="Description" className="custom-textarea" />);
        expect(screen.getByLabelText('Description')).toHaveClass('custom-textarea');
    });
});
