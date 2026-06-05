import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '../../../test/test-utils';
import { MachineIdentitiesSection } from '../MachineIdentitiesSection';

const createMutate = vi.fn();
const transitionMutate = vi.fn();
let isAdmin = true;

vi.mock('../api', () => ({
    useMachineIdentities: () => ({
        data: [
            { id: 1, projectId: 3, name: 'ci-runner', identityType: 'ci', state: 'active', description: 'builds' },
            { id: 2, projectId: 3, name: 'paused-bot', identityType: 'automation', state: 'suspended', description: '' },
        ],
        isLoading: false,
    }),
    useCreateMachineIdentity: () => ({ mutate: createMutate, isPending: false }),
    useTransitionMachineIdentity: () => ({ mutate: transitionMutate, isPending: false }),
}));

vi.mock('../../auth', () => ({
    useAuth: () => ({ isAdmin }),
}));

beforeEach(() => {
    createMutate.mockClear();
    transitionMutate.mockClear();
    isAdmin = true;
});

describe('MachineIdentitiesSection', () => {
    it('lists machine identities with their state', () => {
        render(<MachineIdentitiesSection projectId={3} />);

        expect(screen.getByText('Machine identities')).toBeInTheDocument();
        expect(screen.getByText('ci-runner')).toBeInTheDocument();
        expect(screen.getByText('paused-bot')).toBeInTheDocument();
        expect(screen.getByText('active')).toBeInTheDocument();
        expect(screen.getByText('suspended')).toBeInTheDocument();
    });

    it('an active identity offers suspend + revoke; a suspended one offers reactivate + revoke', () => {
        render(<MachineIdentitiesSection projectId={3} />);

        // active → suspend
        fireEvent.click(screen.getByRole('button', { name: /^suspend$/i }));
        expect(transitionMutate).toHaveBeenCalledWith(
            { machineId: 1, action: 'suspend' },
            expect.anything()
        );

        // suspended → reactivate (activate action)
        fireEvent.click(screen.getByRole('button', { name: /reactivate/i }));
        expect(transitionMutate).toHaveBeenCalledWith(
            { machineId: 2, action: 'activate' },
            expect.anything()
        );
    });

    it('creates a machine identity with the selected type', () => {
        render(<MachineIdentitiesSection projectId={3} />);

        fireEvent.change(screen.getByPlaceholderText('Machine identity name…'), {
            target: { value: 'deploy-key' },
        });
        fireEvent.click(screen.getByRole('button', { name: /^add$/i }));

        expect(createMutate).toHaveBeenCalledTimes(1);
        expect(createMutate.mock.calls[0][0]).toMatchObject({
            name: 'deploy-key',
            identityType: 'ci',
        });
    });

    it('hides management controls (create + lifecycle) for non-admins', () => {
        isAdmin = false;
        render(<MachineIdentitiesSection projectId={3} />);

        // List is still visible (read-only segmentation)…
        expect(screen.getByText('ci-runner')).toBeInTheDocument();
        // …but no create input and no lifecycle actions.
        expect(screen.queryByPlaceholderText('Machine identity name…')).not.toBeInTheDocument();
        expect(screen.queryByRole('button', { name: /^suspend$/i })).not.toBeInTheDocument();
        expect(screen.queryByRole('button', { name: /revoke/i })).not.toBeInTheDocument();
    });
});
