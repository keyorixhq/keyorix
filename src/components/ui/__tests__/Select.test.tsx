import * as React from 'react';
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { Select } from '../Select';

const OPTIONS = [
    { value: 'a', label: 'Option A' },
    { value: 'b', label: 'Option B' },
    { value: 'c', label: 'Option C', disabled: true },
];

describe('Select', () => {
    it('renders a label and all options', () => {
        render(<Select label="Type" options={OPTIONS} />);
        expect(screen.getByLabelText('Type')).toBeInTheDocument();
        expect(screen.getByRole('option', { name: 'Option A' })).toBeInTheDocument();
        expect(screen.getByRole('option', { name: 'Option C' })).toBeDisabled();
    });

    it('renders a placeholder as a disabled option', () => {
        render(<Select options={OPTIONS} placeholder="Choose…" />);
        const placeholder = screen.getByRole('option', { name: 'Choose…' });
        expect(placeholder).toBeDisabled();
    });

    it('calls onChange with the native event', () => {
        const onChange = vi.fn();
        render(<Select label="Type" options={OPTIONS} onChange={onChange} />);
        fireEvent.change(screen.getByLabelText('Type'), { target: { value: 'b' } });
        expect(onChange).toHaveBeenCalledOnce();
    });

    it('shows error state with aria-invalid and error message', () => {
        render(<Select label="Type" options={OPTIONS} error="Required" />);
        expect(screen.getByLabelText('Type')).toHaveAttribute('aria-invalid', 'true');
        expect(screen.getByRole('alert')).toHaveTextContent('Required');
    });

    it('shows helper text when no error', () => {
        render(<Select label="Type" options={OPTIONS} helperText="Pick one" />);
        expect(screen.getByText('Pick one')).toBeInTheDocument();
    });

    it('hides helper text when an error is present', () => {
        render(<Select label="Type" options={OPTIONS} error="Bad" helperText="Pick one" />);
        expect(screen.queryByText('Pick one')).not.toBeInTheDocument();
    });

    it('can be disabled', () => {
        render(<Select label="Type" options={OPTIONS} disabled />);
        expect(screen.getByLabelText('Type')).toBeDisabled();
    });

    it('forwards refs', () => {
        const ref = React.createRef<HTMLSelectElement>();
        render(<Select ref={ref} options={OPTIONS} />);
        expect(ref.current).toBeInstanceOf(HTMLSelectElement);
    });
});
