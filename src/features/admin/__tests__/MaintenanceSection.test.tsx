import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '../../../test/test-utils';
import { MaintenanceSection } from '../MaintenanceSection';

const anomalyMutate = vi.fn();
const rotationMutate = vi.fn();
const expiryMutate = vi.fn();
const complianceMutate = vi.fn();

vi.mock('../api', () => ({
    useRunAnomalyAlerts: () => ({ mutate: anomalyMutate, isPending: false }),
    useRunRotationReminders: () => ({ mutate: rotationMutate, isPending: false }),
    useRunExpiryReminders: () => ({ mutate: expiryMutate, isPending: false }),
    useRunComplianceDigest: () => ({ mutate: complianceMutate, isPending: false }),
}));

beforeEach(() => {
    anomalyMutate.mockReset();
    rotationMutate.mockReset();
    expiryMutate.mockReset();
    complianceMutate.mockReset();
});

describe('MaintenanceSection', () => {
    it('renders a run button for each job', () => {
        render(<MaintenanceSection />);
        expect(screen.getByText('Maintenance')).toBeInTheDocument();
        for (const label of ['Anomaly alerts', 'Rotation reminders', 'Expiry reminders', 'Compliance digest']) {
            expect(screen.getByRole('button', { name: label })).toBeInTheDocument();
        }
    });

    it('runs the job and surfaces the result count on success', async () => {
        anomalyMutate.mockImplementation((_v, opts) => opts.onSuccess({ alerted: 3 }));
        render(<MaintenanceSection />);
        fireEvent.click(screen.getByRole('button', { name: 'Anomaly alerts' }));
        expect(anomalyMutate).toHaveBeenCalledTimes(1);
        expect(await screen.findByText(/Broadcast 3 anomaly alert\(s\)\./)).toBeInTheDocument();
    });

    it('surfaces an error message on failure', async () => {
        rotationMutate.mockImplementation((_v, opts) => opts.onError({ response: { data: { error: 'nope' } } }));
        render(<MaintenanceSection />);
        fireEvent.click(screen.getByRole('button', { name: 'Rotation reminders' }));
        expect(await screen.findByText('nope')).toBeInTheDocument();
    });

    it('reports the no-op case for the compliance digest', async () => {
        complianceMutate.mockImplementation((_v, opts) => opts.onSuccess({ sent: false }));
        render(<MaintenanceSection />);
        fireEvent.click(screen.getByRole('button', { name: 'Compliance digest' }));
        await waitFor(() => expect(screen.getByText(/No compliance digest sent/)).toBeInTheDocument());
    });
});
