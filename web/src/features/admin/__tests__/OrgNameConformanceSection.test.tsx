import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '../../../test/test-utils';
import { OrgNameConformanceSection } from '../OrgNameConformanceSection';

let mockData: any = undefined;
vi.mock('../api', () => ({
    useDeploymentNameConformance: () => ({ data: mockData }),
}));

describe('OrgNameConformanceSection', () => {
    it('renders nothing for non-admins (undefined data)', () => {
        mockData = undefined;
        const { container } = render(<OrgNameConformanceSection />);
        expect(container).toBeEmptyDOMElement();
    });

    it('renders nothing when no policy is configured', () => {
        mockData = { policy_enabled: false, total_secrets: 0, violations: [] };
        const { container } = render(<OrgNameConformanceSection />);
        expect(container).toBeEmptyDOMElement();
    });

    it('renders nothing when the policy is on but every name conforms', () => {
        mockData = { policy_enabled: true, total_secrets: 5, violations: [] };
        const { container } = render(<OrgNameConformanceSection />);
        expect(container).toBeEmptyDOMElement();
    });

    it('lists each violation with its project and reason', () => {
        mockData = {
            policy_enabled: true,
            total_secrets: 5,
            violations: [
                {
                    id: 8,
                    name: 'db-pass',
                    type: 'password',
                    reason: 'does not match the required pattern',
                    project_id: 7,
                    project_name: 'web',
                },
                {
                    id: 9,
                    name: 'api key',
                    type: 'token',
                    reason: 'exceeds the 12-character maximum',
                    project_id: 9,
                    project_name: 'api',
                },
            ],
        };
        render(<OrgNameConformanceSection />);
        expect(screen.getByText(/2 secrets violating the naming policy/i)).toBeInTheDocument();
        expect(screen.getByText('db-pass')).toBeInTheDocument();
        expect(screen.getByText('web')).toBeInTheDocument();
        expect(screen.getByText('api')).toBeInTheDocument();
        expect(screen.getByText(/exceeds the 12-character maximum/i)).toBeInTheDocument();
    });

    it('can be dismissed', () => {
        mockData = {
            policy_enabled: true,
            total_secrets: 2,
            violations: [
                { id: 8, name: 'db-pass', type: 'password', reason: 'bad', project_id: 7, project_name: 'web' },
            ],
        };
        render(<OrgNameConformanceSection />);
        fireEvent.click(screen.getByRole('button', { name: /dismiss/i }));
        expect(screen.queryByText(/violating the naming policy/i)).not.toBeInTheDocument();
    });
});
