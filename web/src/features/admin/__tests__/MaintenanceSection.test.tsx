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

    it('defaults the anomaly count to 0 when the result omits it', async () => {
        anomalyMutate.mockImplementation((_v, opts) => opts.onSuccess({}));
        render(<MaintenanceSection />);
        fireEvent.click(screen.getByRole('button', { name: 'Anomaly alerts' }));
        expect(await screen.findByText(/Broadcast 0 anomaly alert\(s\)\./)).toBeInTheDocument();
    });

    it('runs the rotation-reminders job and surfaces the sent count on success', async () => {
        rotationMutate.mockImplementation((_v, opts) => opts.onSuccess({ sent: 5 }));
        render(<MaintenanceSection />);
        fireEvent.click(screen.getByRole('button', { name: 'Rotation reminders' }));
        expect(await screen.findByText(/Sent 5 rotation reminder\(s\)\./)).toBeInTheDocument();
    });

    it('defaults the rotation-reminders count to 0 when the result omits it', async () => {
        rotationMutate.mockImplementation((_v, opts) => opts.onSuccess({}));
        render(<MaintenanceSection />);
        fireEvent.click(screen.getByRole('button', { name: 'Rotation reminders' }));
        expect(await screen.findByText(/Sent 0 rotation reminder\(s\)\./)).toBeInTheDocument();
    });

    it('runs the expiry-reminders job and surfaces the sent count on success', async () => {
        expiryMutate.mockImplementation((_v, opts) => opts.onSuccess({ sent: 2 }));
        render(<MaintenanceSection />);
        fireEvent.click(screen.getByRole('button', { name: 'Expiry reminders' }));
        expect(await screen.findByText(/Sent 2 expiry reminder\(s\)\./)).toBeInTheDocument();
    });

    it('defaults the expiry-reminders count to 0 when the result omits it', async () => {
        expiryMutate.mockImplementation((_v, opts) => opts.onSuccess({}));
        render(<MaintenanceSection />);
        fireEvent.click(screen.getByRole('button', { name: 'Expiry reminders' }));
        expect(await screen.findByText(/Sent 0 expiry reminder\(s\)\./)).toBeInTheDocument();
    });

    it('surfaces an error message when the expiry-reminders job fails', async () => {
        expiryMutate.mockImplementation((_v, opts) => opts.onError({ response: { data: { error: 'boom' } } }));
        render(<MaintenanceSection />);
        fireEvent.click(screen.getByRole('button', { name: 'Expiry reminders' }));
        expect(await screen.findByText('boom')).toBeInTheDocument();
    });

    it('reports the sent case for the compliance digest', async () => {
        complianceMutate.mockImplementation((_v, opts) => opts.onSuccess({ sent: true }));
        render(<MaintenanceSection />);
        fireEvent.click(screen.getByRole('button', { name: 'Compliance digest' }));
        await waitFor(() => expect(screen.getByText('Compliance digest sent.')).toBeInTheDocument());
    });

    it('surfaces an error message on failure', async () => {
        rotationMutate.mockImplementation((_v, opts) => opts.onError({ response: { data: { error: 'nope' } } }));
        render(<MaintenanceSection />);
        fireEvent.click(screen.getByRole('button', { name: 'Rotation reminders' }));
        expect(await screen.findByText('nope')).toBeInTheDocument();
    });

    it('falls back to the error message when there is no server error payload', async () => {
        rotationMutate.mockImplementation((_v, opts) => opts.onError({ message: 'network down' }));
        render(<MaintenanceSection />);
        fireEvent.click(screen.getByRole('button', { name: 'Rotation reminders' }));
        expect(await screen.findByText('network down')).toBeInTheDocument();
    });

    it('falls back to a generic message when the error has neither a server payload nor a message', async () => {
        rotationMutate.mockImplementation((_v, opts) => opts.onError({}));
        render(<MaintenanceSection />);
        fireEvent.click(screen.getByRole('button', { name: 'Rotation reminders' }));
        expect(await screen.findByText('Job failed.')).toBeInTheDocument();
    });

    it('reports the no-op case for the compliance digest', async () => {
        complianceMutate.mockImplementation((_v, opts) => opts.onSuccess({ sent: false }));
        render(<MaintenanceSection />);
        fireEvent.click(screen.getByRole('button', { name: 'Compliance digest' }));
        await waitFor(() => expect(screen.getByText(/No compliance digest sent/)).toBeInTheDocument());
    });

    it('dismisses the success alert', async () => {
        anomalyMutate.mockImplementation((_v, opts) => opts.onSuccess({ alerted: 1 }));
        render(<MaintenanceSection />);
        fireEvent.click(screen.getByRole('button', { name: 'Anomaly alerts' }));
        const successAlert = await screen.findByText(/Broadcast 1 anomaly alert\(s\)\./);
        fireEvent.click(screen.getByRole('button', { name: /dismiss/i }));
        expect(successAlert).not.toBeInTheDocument();
    });

    it('dismisses the error alert', async () => {
        rotationMutate.mockImplementation((_v, opts) => opts.onError({ response: { data: { error: 'nope' } } }));
        render(<MaintenanceSection />);
        fireEvent.click(screen.getByRole('button', { name: 'Rotation reminders' }));
        const errorAlert = await screen.findByText('nope');
        fireEvent.click(screen.getByRole('button', { name: /dismiss/i }));
        expect(errorAlert).not.toBeInTheDocument();
    });
});
