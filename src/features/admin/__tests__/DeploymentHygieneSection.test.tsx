import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '../../../test/test-utils';
import { DeploymentHygieneSection } from '../DeploymentHygieneSection';

const ZERO = {
    orphaned_secrets: 0,
    unused_secrets: 0,
    expiring_secrets: 0,
    stale_machine_identities: 0,
    rotation_overdue: 0,
};

let mockData: any = undefined;
vi.mock('../api', () => ({
    useDeploymentHygiene: () => ({ data: mockData }),
}));

describe('DeploymentHygieneSection', () => {
    it('renders nothing when there is no debt', () => {
        mockData = { totals: { ...ZERO }, projects: [] };
        const { container } = render(<DeploymentHygieneSection />);
        expect(container).toBeEmptyDOMElement();
    });

    it('renders nothing for non-admins (empty/undefined data)', () => {
        mockData = undefined;
        const { container } = render(<DeploymentHygieneSection />);
        expect(container).toBeEmptyDOMElement();
    });

    it('renders totals and the per-project breakdown when there is debt', () => {
        mockData = {
            totals: { ...ZERO, orphaned_secrets: 1, unused_secrets: 3, rotation_overdue: 1 },
            projects: [
                {
                    project_id: 7,
                    project_name: 'web',
                    ...ZERO,
                    orphaned_secrets: 1,
                    unused_secrets: 2,
                    rotation_overdue: 1,
                },
                { project_id: 9, project_name: 'api', ...ZERO, unused_secrets: 1 },
            ],
        };
        render(<DeploymentHygieneSection />);
        expect(screen.getByText(/debt across 2 projects/i)).toBeInTheDocument();
        expect(screen.getByText('web')).toBeInTheDocument();
        expect(screen.getByText('api')).toBeInTheDocument();
        // Per-project total chips: web = 1+2+1 = 4, api = 1.
        expect(screen.getByText('4 total')).toBeInTheDocument();
        expect(screen.getByText('1 total')).toBeInTheDocument();
    });

    it('treats missing signal counts as 0 (totals, per-signal tiles, and per-project rows)', () => {
        mockData = {
            // Totals omit some keys entirely (not just zeroed) to exercise the `?? 0` fallback.
            totals: { orphaned_secrets: 1 },
            projects: [
                // This project omits every signal key, so its row shows no detail text
                // and a "0 total" chip via the same fallback.
                { project_id: 4, project_name: 'empty-signals' },
            ],
        };
        render(<DeploymentHygieneSection />);
        expect(screen.getByText(/debt across 1 project/i)).toBeInTheDocument();
        expect(screen.getByText('empty-signals')).toBeInTheDocument();
        expect(screen.getByText('0 total')).toBeInTheDocument();
    });

    it('can be dismissed', () => {
        mockData = {
            totals: { ...ZERO, orphaned_secrets: 1 },
            projects: [{ project_id: 7, project_name: 'web', ...ZERO, orphaned_secrets: 1 }],
        };
        render(<DeploymentHygieneSection />);
        fireEvent.click(screen.getByRole('button', { name: /dismiss/i }));
        expect(screen.queryByText(/debt across/i)).not.toBeInTheDocument();
    });
});
