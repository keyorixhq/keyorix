import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor, act } from '../../../test/test-utils';
import { MachineTokensPanel } from '../MachineTokensPanel';
import { DEFAULT_SENSITIVE_IDLE_MS } from '../../../hooks/useAutoClearOnIdle';

const issueMutate = vi.fn();
const revokeMutate = vi.fn();
const classifyMutate = vi.fn();

let tokensData: any[] = [];
let tokensLoading = false;

const defaultTokens = [
    { id: 11, name: 'ci-token', prefix: 'kx_machine_ab12cd', revoked: false, classification: 'restricted' },
    { id: 12, name: 'old', prefix: 'kx_machine_ee99ff', revoked: true, classification: '' },
];

vi.mock('../api', () => ({
    useMachineTokens: () => ({ data: tokensData, isLoading: tokensLoading }),
    useIssueMachineToken: () => ({ mutate: issueMutate, isPending: false }),
    useRevokeMachineToken: () => ({ mutate: revokeMutate, isPending: false }),
    useClassifyMachineToken: () => ({ mutate: classifyMutate, isPending: false }),
}));

beforeEach(() => {
    tokensData = defaultTokens;
    tokensLoading = false;
    issueMutate.mockReset();
    revokeMutate.mockReset();
    classifyMutate.mockReset();
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

    it('shows a loading message while tokens load', () => {
        tokensLoading = true;
        render(<MachineTokensPanel projectId={3} machineId={7} canManage />);
        expect(screen.getByText('Loading tokens…')).toBeInTheDocument();
    });

    it('shows an empty state when there are no tokens', () => {
        tokensData = [];
        render(<MachineTokensPanel projectId={3} machineId={7} canManage />);
        expect(screen.getByText('No tokens issued yet.')).toBeInTheDocument();
    });

    it('does not issue with a blank/whitespace-only name', () => {
        render(<MachineTokensPanel projectId={3} machineId={7} canManage />);
        fireEvent.change(screen.getByPlaceholderText('Token name…'), { target: { value: '   ' } });
        fireEvent.click(screen.getByRole('button', { name: /issue token/i }));
        expect(issueMutate).not.toHaveBeenCalled();
    });

    it('issues via the Enter key and shows the one-time token modal, then Copy + Done', async () => {
        issueMutate.mockImplementation((_vars, opts) => {
            opts.onSuccess({ token: 'kx_machine_raw_secret', id: 99, prefix: 'kx_machine_9999', classification: '' });
        });

        render(<MachineTokensPanel projectId={3} machineId={7} canManage />);
        const nameInput = screen.getByPlaceholderText('Token name…');
        fireEvent.change(nameInput, { target: { value: 'ci-deploy' } });
        fireEvent.keyDown(nameInput, { key: 'Enter' });

        expect(issueMutate).toHaveBeenCalledTimes(1);
        expect(screen.getByText('Machine token issued')).toBeInTheDocument();
        expect(screen.getByText('kx_machine_raw_secret')).toBeInTheDocument();
        // The name field is cleared after a successful issue.
        expect((screen.getByPlaceholderText('Token name…') as HTMLInputElement).value).toBe('');

        fireEvent.click(screen.getByRole('button', { name: 'Copy' }));
        expect(navigator.clipboard.writeText).toHaveBeenCalledWith('kx_machine_raw_secret');
        await waitFor(() => expect(screen.getByRole('button', { name: 'Copied' })).toBeInTheDocument());

        fireEvent.click(screen.getByRole('button', { name: 'Done' }));
        expect(screen.queryByText('Machine token issued')).not.toBeInTheDocument();
    });

    it('an Enter keypress on the name field is a no-op when Enter is not pressed', () => {
        render(<MachineTokensPanel projectId={3} machineId={7} canManage />);
        const nameInput = screen.getByPlaceholderText('Token name…');
        fireEvent.change(nameInput, { target: { value: 'ci-deploy' } });
        fireEvent.keyDown(nameInput, { key: 'a' });
        expect(issueMutate).not.toHaveBeenCalled();
    });

    it('shows the server message when issuing a token fails', () => {
        issueMutate.mockImplementation((_vars, opts) => {
            opts.onError({ response: { data: { message: 'Quota exceeded' } } });
        });

        render(<MachineTokensPanel projectId={3} machineId={7} canManage />);
        fireEvent.change(screen.getByPlaceholderText('Token name…'), { target: { value: 'deploy' } });
        fireEvent.click(screen.getByRole('button', { name: /issue token/i }));

        expect(screen.getByText('Quota exceeded')).toBeInTheDocument();
    });

    it('reclassifying to the same value is a no-op', () => {
        render(<MachineTokensPanel projectId={3} machineId={7} canManage />);
        const picker = screen.getByLabelText('Classification for token kx_machine_ab12cd') as HTMLSelectElement;
        fireEvent.change(picker, { target: { value: 'restricted' } });
        expect(classifyMutate).not.toHaveBeenCalled();
    });

    it('shows the error.error field fallback when reclassifying fails', () => {
        classifyMutate.mockImplementation((_vars, opts) => {
            opts.onError({ response: { data: { error: 'not permitted' } } });
        });

        render(<MachineTokensPanel projectId={3} machineId={7} canManage />);
        const picker = screen.getByLabelText('Classification for token kx_machine_ab12cd') as HTMLSelectElement;
        fireEvent.change(picker, { target: { value: 'confidential' } });

        expect(screen.getByText('not permitted')).toBeInTheDocument();
    });

    it('revokes an active token and surfaces a fallback error when the server gives no detail', () => {
        revokeMutate.mockImplementation((_id, opts) => {
            opts.onError({});
        });

        render(<MachineTokensPanel projectId={3} machineId={7} canManage />);
        fireEvent.click(screen.getByTitle('Revoke token'));

        expect(revokeMutate).toHaveBeenCalledWith(11, expect.anything());
        expect(screen.getByText('Failed to revoke token.')).toBeInTheDocument();
    });

    it('hides the revoke action for already-revoked tokens', () => {
        render(<MachineTokensPanel projectId={3} machineId={7} canManage />);
        // Only one active (non-revoked) token → only one revoke button.
        expect(screen.getAllByTitle('Revoke token')).toHaveLength(1);
    });

    // G28: the one-time token must not linger indefinitely with no explicit close.
    describe('auto-clear (G28)', () => {
        afterEach(() => {
            vi.useRealTimers();
        });

        it('auto-closes the token modal after the idle timeout elapses, without an explicit close', async () => {
            issueMutate.mockImplementation((_vars, opts) => {
                opts.onSuccess({
                    token: 'kx_machine_idle_secret',
                    id: 100,
                    prefix: 'kx_machine_idle',
                    classification: '',
                });
            });
            vi.useFakeTimers();

            render(<MachineTokensPanel projectId={3} machineId={7} canManage />);
            fireEvent.change(screen.getByPlaceholderText('Token name…'), { target: { value: 'idle-test' } });
            fireEvent.click(screen.getByRole('button', { name: /issue token/i }));
            expect(screen.getByText('kx_machine_idle_secret')).toBeInTheDocument();

            await act(async () => {
                await vi.advanceTimersByTimeAsync(DEFAULT_SENSITIVE_IDLE_MS);
            });

            expect(screen.queryByText('kx_machine_idle_secret')).not.toBeInTheDocument();
            expect(screen.queryByText('Machine token issued')).not.toBeInTheDocument();
        });

        it('auto-closes the token modal when the tab is backgrounded, without an explicit close', () => {
            issueMutate.mockImplementation((_vars, opts) => {
                opts.onSuccess({ token: 'kx_machine_bg_secret', id: 101, prefix: 'kx_machine_bg', classification: '' });
            });

            render(<MachineTokensPanel projectId={3} machineId={7} canManage />);
            fireEvent.change(screen.getByPlaceholderText('Token name…'), { target: { value: 'bg-test' } });
            fireEvent.click(screen.getByRole('button', { name: /issue token/i }));
            expect(screen.getByText('kx_machine_bg_secret')).toBeInTheDocument();

            Object.defineProperty(document, 'visibilityState', { value: 'hidden', configurable: true });
            act(() => {
                document.dispatchEvent(new Event('visibilitychange'));
            });

            expect(screen.queryByText('kx_machine_bg_secret')).not.toBeInTheDocument();
            expect(screen.queryByText('Machine token issued')).not.toBeInTheDocument();

            Object.defineProperty(document, 'visibilityState', { value: 'visible', configurable: true });
        });
    });
});
