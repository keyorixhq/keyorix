import { render, screen, fireEvent } from '../../test/test-utils';
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

    it('applies variant styles correctly', () => {
        const { rerender } = render(<Button variant="primary">Primary</Button>);
        expect(screen.getByRole('button')).toHaveClass('bg-blue-600');

        rerender(<Button variant="secondary">Secondary</Button>);
        expect(screen.getByRole('button')).toHaveClass('bg-gray-600');

        rerender(<Button variant="danger">Danger</Button>);
        expect(screen.getByRole('button')).toHaveClass('bg-red-600');
    });

    it('applies size styles correctly', () => {
        const { rerender } = render(<Button size="sm">Small</Button>);
        expect(screen.getByRole('button')).toHaveClass('px-3', 'py-1.5', 'text-sm');

        rerender(<Button size="md">Medium</Button>);
        expect(screen.getByRole('button')).toHaveClass('px-4', 'py-2', 'text-sm');

        rerender(<Button size="lg">Large</Button>);
        expect(screen.getByRole('button')).toHaveClass('px-6', 'py-3', 'text-base');
    });

    it('shows loading state correctly', () => {
        render(<Button loading>Loading</Button>);

        const button = screen.getByRole('button');
        expect(button).toBeDisabled();
        expect(screen.getByText('Loading...')).toBeInTheDocument();
    });

    it('can be disabled', () => {
        render(<Button disabled>Disabled</Button>);

        const button = screen.getByRole('button');
        expect(button).toBeDisabled();
        expect(button).toHaveClass('opacity-50', 'cursor-not-allowed');
    });

    it('renders as different element types', () => {
        render(<Button as="a" href="/test">Link Button</Button>);
        expect(screen.getByRole('link')).toBeInTheDocument();
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