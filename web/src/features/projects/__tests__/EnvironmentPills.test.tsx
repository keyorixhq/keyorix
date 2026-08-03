import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { EnvironmentPills } from '../EnvironmentPills';
import type { ProjectEnvironment } from '../../../services/projects';

const environments = [
    { id: 1, name: 'production' },
    { id: 2, name: 'staging' },
] as ProjectEnvironment[];

describe('EnvironmentPills', () => {
    it('renders a skeleton placeholder while loading', () => {
        const { container } = render(
            <EnvironmentPills environments={environments} activeEnvName="production" onChange={vi.fn()} isLoading />
        );
        expect(container.querySelectorAll('.animate-pulse')).toHaveLength(3);
        expect(screen.queryByRole('button')).not.toBeInTheDocument();
    });

    it('renders nothing when there are no environments and not loading', () => {
        const { container } = render(
            <EnvironmentPills environments={[]} activeEnvName="" onChange={vi.fn()} isLoading={false} />
        );
        expect(container).toBeEmptyDOMElement();
    });

    it('renders a pill per environment with a capitalized label', () => {
        render(<EnvironmentPills environments={environments} activeEnvName="production" onChange={vi.fn()} />);
        expect(screen.getByRole('button', { name: 'Production' })).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Staging' })).toBeInTheDocument();
    });

    it('calls onChange with the environment name when a pill is clicked', () => {
        const onChange = vi.fn();
        render(<EnvironmentPills environments={environments} activeEnvName="production" onChange={onChange} />);
        fireEvent.click(screen.getByRole('button', { name: 'Staging' }));
        expect(onChange).toHaveBeenCalledWith('staging');
    });
});
