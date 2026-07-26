import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '../../../test/test-utils';
import { MachineTokensPanel } from '../MachineTokensPanel';

const issueMutate = vi.fn();
const revokeMutate = vi.fn();
const classifyMutate = vi.fn();

vi.mock('../api', () => ({
    useMachineTokens: () => ({
        data: [
            { id: 11, name: 'ci-token', prefix: 'kx_machine_ab12cd', revoked: false, classification: 'restricted' },
            { id: 12, name: 'old', prefix: 'kx_machine_ee99ff', revoked: true, classification: '' },
        ],
        isLoading: false,
    }),
    useIssueMachineToken: () => ({ mutate: issueMutate, isPending: false }),
    useRevokeMachineToken: () => ({ mutate: revokeMutate, isPending: false }),
    useClassifyMachineToken: () => ({ mutate: classifyMutate, isPending: false }),
}));

beforeEach(() => {
    issueMutate.mockClear();
    revokeMutate.mockClear();
    classifyMutate.mockClear();
});

describe('MachineTokensPanel', () => {
    it('admins issue tokens and reclassify them', () => {
        render(<MachineTokensPanel projectId={3} machineId={7} canManage />);

        // Issue requires a name.
        fireEvent.change(screen.getByPlaceholderText('Token name…'), { target: { value: 'deploy' } });
        fireEvent.click(screen.getByRole('button', { name: /issue token/i }));
        expect(issueMutate).toHaveBeenCalledTimes(1);
        expect(issueMutate.mock.calls[0][0]).toMatchObject({ name: 'deploy' });

        // Reclassify the active token.
        const picker = screen.getByLabelText('Classification for token kx_machine_ab12cd') as HTMLSelectElement;
        expect(picker.value).toBe('restricted');
        fireEvent.change(picker, { target: { value: 'confidential' } });
        expect(classifyMutate).toHaveBeenCalledWith({ tokenId: 11, classification: 'confidential' }, expect.anything());
    });

    it('non-admins see read-only classification badges, no issue/revoke', () => {
        render(<MachineTokensPanel projectId={3} machineId={7} canManage={false} />);

        expect(screen.queryByPlaceholderText('Token name…')).not.toBeInTheDocument();
        const badges = screen.getAllByTestId('mt-classification-badge');
        expect(badges[0]).toHaveTextContent('Restricted');
        expect(screen.queryByLabelText('Classification for token kx_machine_ab12cd')).not.toBeInTheDocument();
    });
});
