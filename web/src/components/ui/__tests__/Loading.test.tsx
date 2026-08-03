import React from 'react';
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { Spinner, LoadingOverlay, Skeleton, Progress, LoadingPage, Loading } from '../Loading';

describe('Spinner', () => {
    it('renders with default md size and primary color classes', () => {
        const { container } = render(<Spinner />);
        const svg = container.querySelector('svg');
        expect(svg).toHaveClass('h-6', 'w-6', 'text-blue-600');
    });

    it.each([
        ['sm', 'h-4', 'w-4'],
        ['md', 'h-6', 'w-6'],
        ['lg', 'h-8', 'w-8'],
        ['xl', 'h-12', 'w-12'],
    ] as const)('applies %s size classes', (size, hClass, wClass) => {
        const { container } = render(<Spinner size={size} />);
        expect(container.querySelector('svg')).toHaveClass(hClass, wClass);
    });

    it.each([
        ['primary', 'text-blue-600'],
        ['secondary', 'text-gray-600'],
        ['white', 'text-white'],
    ] as const)('applies the %s color class', (color, colorClass) => {
        const { container } = render(<Spinner color={color} />);
        expect(container.querySelector('svg')).toHaveClass(colorClass);
    });

    it('applies a custom className', () => {
        const { container } = render(<Spinner className="custom-spinner" />);
        expect(container.querySelector('svg')).toHaveClass('custom-spinner');
    });
});

describe('LoadingOverlay', () => {
    it('always renders children', () => {
        render(
            <LoadingOverlay isLoading={false}>
                <div>Content</div>
            </LoadingOverlay>
        );
        expect(screen.getByText('Content')).toBeInTheDocument();
    });

    it('does not show the overlay message when isLoading is false', () => {
        render(
            <LoadingOverlay isLoading={false}>
                <div>Content</div>
            </LoadingOverlay>
        );
        expect(screen.queryByText('Loading...')).not.toBeInTheDocument();
    });

    it('shows the default overlay message when isLoading is true', () => {
        render(
            <LoadingOverlay isLoading>
                <div>Content</div>
            </LoadingOverlay>
        );
        expect(screen.getByText('Loading...')).toBeInTheDocument();
        expect(screen.getByText('Content')).toBeInTheDocument();
    });

    it('shows a custom message when provided', () => {
        render(
            <LoadingOverlay isLoading message="Fetching data…">
                <div>Content</div>
            </LoadingOverlay>
        );
        expect(screen.getByText('Fetching data…')).toBeInTheDocument();
    });

    it('applies a custom className to the wrapper', () => {
        const { container } = render(
            <LoadingOverlay isLoading={false} className="custom-overlay">
                <div>Content</div>
            </LoadingOverlay>
        );
        expect(container.firstChild).toHaveClass('custom-overlay');
    });
});

describe('Skeleton', () => {
    it('renders a single line by default with the full-width class', () => {
        const { container } = render(<Skeleton />);
        const lines = container.querySelectorAll('.animate-pulse > div');
        expect(lines).toHaveLength(1);
        expect(lines[0]).toHaveClass('w-full', 'h-4');
    });

    it('renders multiple lines, shortening only the last one', () => {
        const { container } = render(<Skeleton lines={3} />);
        const lines = container.querySelectorAll('.animate-pulse > div');
        expect(lines).toHaveLength(3);
        expect(lines[0]).toHaveClass('w-full');
        expect(lines[1]).toHaveClass('w-full');
        expect(lines[2]).toHaveClass('w-3/4');
    });

    it('applies a custom height class to every line', () => {
        const { container } = render(<Skeleton height="h-8" />);
        const line = container.querySelector('.animate-pulse > div');
        expect(line).toHaveClass('h-8');
    });

    it('applies a custom className to the wrapper', () => {
        const { container } = render(<Skeleton className="custom-skeleton" />);
        expect(container.firstChild).toHaveClass('custom-skeleton');
    });
});

describe('Progress', () => {
    it('renders with default props: md size, primary color, no label row', () => {
        const { container } = render(<Progress value={50} />);
        expect(screen.queryByText(/%$/)).not.toBeInTheDocument();
        expect(container.querySelector('.h-2.bg-blue-600')).toBeInTheDocument();
    });

    it('clamps the percentage at 0 when value is negative', () => {
        const { container } = render(<Progress value={-20} showLabel />);
        expect(screen.getByText('-20/100')).toBeInTheDocument();
        const bar = container.querySelector('[style*="width"]') as HTMLElement;
        expect(bar.style.width).toBe('0%');
    });

    it('clamps the percentage at 100 when value exceeds max', () => {
        const { container } = render(<Progress value={150} max={100} />);
        const bar = container.querySelector('[style*="width"]') as HTMLElement;
        expect(bar.style.width).toBe('100%');
    });

    it('shows a rounded percentage label and the value/max span when showLabel is true', () => {
        render(<Progress value={33} showLabel />);
        expect(screen.getByText('33%')).toBeInTheDocument();
        expect(screen.getByText('33/100')).toBeInTheDocument();
    });

    it('prefers a custom label over the percentage, and hides the value/max span', () => {
        render(<Progress value={40} label="Uploading" showLabel />);
        expect(screen.getByText('Uploading')).toBeInTheDocument();
        expect(screen.queryByText('40/100')).not.toBeInTheDocument();
        expect(screen.queryByText('40%')).not.toBeInTheDocument();
    });

    it('renders a custom label even without showLabel', () => {
        render(<Progress value={40} label="Custom label" />);
        expect(screen.getByText('Custom label')).toBeInTheDocument();
    });

    it('renders no label row when neither showLabel nor label is given', () => {
        render(<Progress value={40} />);
        expect(screen.queryByText(/\d+%/)).not.toBeInTheDocument();
        expect(screen.queryByText(/\d+\/\d+/)).not.toBeInTheDocument();
    });

    it.each([
        ['sm', 'h-1'],
        ['md', 'h-2'],
        ['lg', 'h-3'],
    ] as const)('applies the %s size class', (size, sizeClass) => {
        const { container } = render(<Progress value={50} size={size} />);
        expect(container.querySelector(`.${sizeClass}`)).toBeInTheDocument();
    });

    it.each([
        ['primary', 'bg-blue-600'],
        ['success', 'bg-green-600'],
        ['warning', 'bg-yellow-600'],
        ['danger', 'bg-red-600'],
    ] as const)('applies the %s color class', (color, colorClass) => {
        const { container } = render(<Progress value={50} color={color} />);
        expect(container.querySelector(`.${colorClass}`)).toBeInTheDocument();
    });

    it('applies a custom className to the wrapper', () => {
        const { container } = render(<Progress value={50} className="custom-progress" />);
        expect(container.firstChild).toHaveClass('custom-progress');
    });
});

describe('LoadingPage', () => {
    it('renders a full-page spinner with the default message', () => {
        render(<LoadingPage />);
        expect(screen.getByText('Loading...')).toBeInTheDocument();
    });

    it('renders a custom message', () => {
        render(<LoadingPage message="Preparing your dashboard…" />);
        expect(screen.getByText('Preparing your dashboard…')).toBeInTheDocument();
    });

    it('applies a custom className', () => {
        const { container } = render(<LoadingPage className="custom-page" />);
        expect(container.firstChild).toHaveClass('custom-page');
    });
});

describe('Loading', () => {
    it('is an alias for LoadingPage', () => {
        expect(Loading).toBe(LoadingPage);
    });
});
