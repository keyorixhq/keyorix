import { render, screen, fireEvent } from '../../test/test-utils';
import { Input } from '../Input';

describe('Input', () => {
    it('renders with label', () => {
        render(<Input label="Email" />);
        expect(screen.getByLabelText('Email')).toBeInTheDocument();
    });

    it('handles value changes', () => {
        const handleChange = vi.fn();
        render(<Input label="Email" onChange={handleChange} />);

        const input = screen.getByLabelText('Email');
        fireEvent.change(input, { target: { value: 'test@example.com' } });

        expect(handleChange).toHaveBeenCalledWith(
            expect.objectContaining({
                target: expect.objectContaining({ value: 'test@example.com' })
            })
        );
    });

    it('shows error state correctly', () => {
        render(<Input label="Email" error="Invalid email" />);

        const input = screen.getByLabelText('Email');
        expect(input).toHaveClass('border-red-500');
        expect(screen.getByText('Invalid email')).toBeInTheDocument();
    });

    it('shows help text', () => {
        render(<Input label="Password" helpText="Must be at least 8 characters" />);
        expect(screen.getByText('Must be at least 8 characters')).toBeInTheDocument();
    });

    it('can be disabled', () => {
        render(<Input label="Email" disabled />);
        expect(screen.getByLabelText('Email')).toBeDisabled();
    });

    it('supports different input types', () => {
        const { rerender } = render(<Input label="Email" type="email" />);
        expect(screen.getByLabelText('Email')).toHaveAttribute('type', 'email');

        rerender(<Input label="Password" type="password" />);
        expect(screen.getByLabelText('Password')).toHaveAttribute('type', 'password');
    });

    it('shows required indicator', () => {
        render(<Input label="Email" required />);
        expect(screen.getByText('*')).toBeInTheDocument();
    });

    it('supports placeholder text', () => {
        render(<Input label="Email" placeholder="Enter your email" />);
        expect(screen.getByPlaceholderText('Enter your email')).toBeInTheDocument();
    });

    it('forwards refs correctly', () => {
        const ref = React.createRef<HTMLInputElement>();
        render(<Input ref={ref} label="Email" />);
        expect(ref.current).toBeInstanceOf(HTMLInputElement);
    });

    it('supports custom className', () => {
        render(<Input label="Email" className="custom-input" />);
        expect(screen.getByLabelText('Email')).toHaveClass('custom-input');
    });
});