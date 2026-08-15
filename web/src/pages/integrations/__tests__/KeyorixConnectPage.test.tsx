import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor, act } from '../../../test/test-utils';
import { KeyorixConnectPage } from '../KeyorixConnectPage';
import { DEFAULT_SENSITIVE_IDLE_MS } from '../../../hooks/useAutoClearOnIdle';

let connectorsData: string[];
let connectorsState: { data: string[]; isLoading: boolean; isError: boolean };
const readMutate = vi.fn();

interface Grant {
    id: number;
    role_id: number;
    connector: string;
    ref_prefix: string;
}
let grantsState: { data: Grant[]; isLoading: boolean; isError: boolean; error?: unknown };
const createGrantMutate = vi.fn();
const deleteGrantMutate = vi.fn();
let readState: { isPending: boolean };
let createGrantState: { isPending: boolean };
let deleteGrantState: { isPending: boolean };

vi.mock('../../../features/connect', () => ({
    useConnectors: () => connectorsState,
    useReadFederatedSecret: () => ({ mutate: readMutate, ...readState }),
    useRefGrants: () => grantsState,
    useCreateRefGrant: () => ({ mutate: createGrantMutate, ...createGrantState }),
    useDeleteRefGrant: () => ({ mutate: deleteGrantMutate, ...deleteGrantState }),
}));

beforeEach(() => {
    connectorsData = ['prod-aws', 'prod-vault'];
    connectorsState = { data: connectorsData, isLoading: false, isError: false };
    grantsState = { data: [], isLoading: false, isError: false };
    readState = { isPending: false };
    createGrantState = { isPending: false };
    deleteGrantState = { isPending: false };
    readMutate.mockReset();
    createGrantMutate.mockReset();
    deleteGrantMutate.mockReset();
});

describe('KeyorixConnectPage', () => {
    it('renders the overview and configured connectors', () => {
        render(<KeyorixConnectPage />);
        expect(screen.getByText('Keyorix Connect')).toBeInTheDocument();
        expect(screen.getByText('Read a federated secret')).toBeInTheDocument();
        const select = screen.getAllByLabelText('Connector')[0] as HTMLSelectElement;
        expect(select).toBeInTheDocument();
        // Both the read panel and the grants panel offer connector <option>s.
        expect(screen.getAllByRole('option', { name: 'prod-aws' }).length).toBeGreaterThan(0);
        expect(screen.getAllByRole('option', { name: 'prod-vault' }).length).toBeGreaterThan(0);
    });

    it('prompts to configure when no connectors exist', () => {
        connectorsState = { data: [], isLoading: false, isError: false };
        render(<KeyorixConnectPage />);
        expect(screen.getByText(/No connectors are configured/i)).toBeInTheDocument();
    });

    it('reads a secret and reveals the value', async () => {
        readMutate.mockImplementation((_vars, opts) =>
            opts.onSuccess({ connector: 'prod-aws', ref: 'prod/db', value: 's3cr3t' })
        );
        render(<KeyorixConnectPage />);

        fireEvent.change(screen.getByLabelText('Reference'), { target: { value: 'prod/db' } });
        fireEvent.click(screen.getByRole('button', { name: /Read secret/i }));

        expect(readMutate).toHaveBeenCalledWith({ connector: 'prod-aws', ref: 'prod/db' }, expect.anything());
        // Value is masked until revealed.
        expect(screen.queryByText('s3cr3t')).not.toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: /Reveal value/i }));
        await waitFor(() => expect(screen.getByText('s3cr3t')).toBeInTheDocument());
    });

    it('clears the fetched value from state on hide, forcing a re-fetch (not a stale display) on re-reveal', async () => {
        readMutate.mockImplementation((_vars, opts) =>
            opts.onSuccess({ connector: 'prod-aws', ref: 'prod/db', value: 's3cr3t' })
        );
        render(<KeyorixConnectPage />);

        fireEvent.change(screen.getByLabelText('Reference'), { target: { value: 'prod/db' } });
        fireEvent.click(screen.getByRole('button', { name: /Read secret/i }));
        expect(readMutate).toHaveBeenCalledTimes(1);

        fireEvent.click(screen.getByRole('button', { name: /Reveal value/i }));
        await waitFor(() => expect(screen.getByText('s3cr3t')).toBeInTheDocument());

        // Hide: the plaintext must be cleared from React state, not just
        // masked again — proven below by the fact that revealing a second
        // time has to re-fetch rather than instantly showing the value.
        fireEvent.click(screen.getByRole('button', { name: /Hide value/i }));
        expect(screen.queryByText('s3cr3t')).not.toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: /Reveal value/i }));
        expect(readMutate).toHaveBeenCalledTimes(2);
        expect(readMutate).toHaveBeenLastCalledWith({ connector: 'prod-aws', ref: 'prod/db' }, expect.anything());
        await waitFor(() => expect(screen.getByText('s3cr3t')).toBeInTheDocument());
    });

    it('clears the fetched value on unmount without throwing', () => {
        readMutate.mockImplementation((_vars, opts) =>
            opts.onSuccess({ connector: 'prod-aws', ref: 'prod/db', value: 's3cr3t' })
        );
        const { unmount } = render(<KeyorixConnectPage />);
        fireEvent.change(screen.getByLabelText('Reference'), { target: { value: 'prod/db' } });
        fireEvent.click(screen.getByRole('button', { name: /Read secret/i }));
        expect(screen.getByRole('button', { name: /Reveal value/i })).toBeInTheDocument();

        expect(() => unmount()).not.toThrow();
    });

    it('surfaces a read error', () => {
        readMutate.mockImplementation((_vars, opts) =>
            opts.onError({ response: { data: { message: 'ref not permitted' } } })
        );
        render(<KeyorixConnectPage />);
        fireEvent.change(screen.getByLabelText('Reference'), { target: { value: 'x' } });
        fireEvent.click(screen.getByRole('button', { name: /Read secret/i }));
        expect(screen.getByText('ref not permitted')).toBeInTheDocument();
    });
});

describe('KeyorixConnectPage — per-reference grants', () => {
    it('lists existing grants (empty pattern shown as all refs)', () => {
        grantsState = {
            data: [
                { id: 1, role_id: 3, connector: 'prod-aws', ref_prefix: 'metrics/' },
                { id: 2, role_id: 4, connector: 'prod-vault', ref_prefix: '' },
            ],
            isLoading: false,
            isError: false,
        };
        render(<KeyorixConnectPage />);
        expect(screen.getByText('Per-reference access (RBAC)')).toBeInTheDocument();
        expect(screen.getByText('metrics/')).toBeInTheDocument();
        expect(screen.getByText('(all refs)')).toBeInTheDocument();
    });

    it('creates a grant from the form', () => {
        render(<KeyorixConnectPage />);
        fireEvent.change(screen.getByLabelText('Role ID'), { target: { value: '3' } });
        fireEvent.change(screen.getByLabelText('Pattern'), { target: { value: 'prod/*/db' } });
        fireEvent.click(screen.getByRole('button', { name: /Add grant/i }));
        expect(createGrantMutate).toHaveBeenCalledWith(
            { roleId: 3, connector: 'prod-aws', refPrefix: 'prod/*/db' },
            expect.anything()
        );
    });

    it('rejects a non-positive role ID before calling the API', () => {
        render(<KeyorixConnectPage />);
        fireEvent.change(screen.getByLabelText('Role ID'), { target: { value: '0' } });
        fireEvent.click(screen.getByRole('button', { name: /Add grant/i }));
        expect(createGrantMutate).not.toHaveBeenCalled();
        expect(screen.getByText(/valid role ID/i)).toBeInTheDocument();
    });

    it('deletes a grant', () => {
        grantsState = {
            data: [{ id: 7, role_id: 3, connector: 'prod-aws', ref_prefix: 'metrics/' }],
            isLoading: false,
            isError: false,
        };
        render(<KeyorixConnectPage />);
        fireEvent.click(screen.getByRole('button', { name: /Delete grant 7/i }));
        expect(deleteGrantMutate).toHaveBeenCalledWith(7);
    });

    it('shows a permission notice on 403', () => {
        grantsState = { data: [], isLoading: false, isError: true, error: { response: { status: 403 } } };
        render(<KeyorixConnectPage />);
        expect(screen.getByText(/Insufficient permissions/i)).toBeInTheDocument();
    });

    it('shows a generic error for a non-403 failure', () => {
        grantsState = { data: [], isLoading: false, isError: true, error: { response: { status: 500 } } };
        render(<KeyorixConnectPage />);
        expect(screen.getByText('Could not load grants')).toBeInTheDocument();
        expect(screen.getByText('Please try again.')).toBeInTheDocument();
    });

    it('shows a loading spinner while grants load', () => {
        grantsState = { data: [], isLoading: true, isError: false };
        const { container } = render(<KeyorixConnectPage />);
        expect(container.querySelector('svg.animate-spin')).toBeInTheDocument();
    });

    it('clears the form fields once a grant is created successfully', () => {
        createGrantMutate.mockImplementation((_vars, opts) => opts.onSuccess());
        render(<KeyorixConnectPage />);
        fireEvent.change(screen.getByLabelText('Role ID'), { target: { value: '3' } });
        fireEvent.change(screen.getByLabelText('Pattern'), { target: { value: 'prod/*/db' } });
        fireEvent.click(screen.getByRole('button', { name: /Add grant/i }));
        expect(screen.getByLabelText('Role ID')).toHaveValue(null);
        expect(screen.getByLabelText('Pattern')).toHaveValue('');
    });

    it('surfaces a create-grant error using the response message', () => {
        createGrantMutate.mockImplementation((_vars, opts) =>
            opts.onError({ response: { data: { message: 'role not found' } } })
        );
        render(<KeyorixConnectPage />);
        fireEvent.change(screen.getByLabelText('Role ID'), { target: { value: '3' } });
        fireEvent.click(screen.getByRole('button', { name: /Add grant/i }));
        expect(screen.getByText('role not found')).toBeInTheDocument();
    });

    it('falls back to the Error message when a create-grant error has no response message', () => {
        createGrantMutate.mockImplementation((_vars, opts) => opts.onError(new Error('boom')));
        render(<KeyorixConnectPage />);
        fireEvent.change(screen.getByLabelText('Role ID'), { target: { value: '3' } });
        fireEvent.click(screen.getByRole('button', { name: /Add grant/i }));
        expect(screen.getByText('boom')).toBeInTheDocument();
    });

    it('falls back to a generic message when a create-grant error has neither a response nor a message', () => {
        createGrantMutate.mockImplementation((_vars, opts) => opts.onError({}));
        render(<KeyorixConnectPage />);
        fireEvent.change(screen.getByLabelText('Role ID'), { target: { value: '3' } });
        fireEvent.click(screen.getByRole('button', { name: /Add grant/i }));
        expect(screen.getByText('Could not create the grant.')).toBeInTheDocument();
    });

    it('changes the grant connector via its select', () => {
        render(<KeyorixConnectPage />);
        fireEvent.change(screen.getAllByLabelText('Connector')[1], { target: { value: 'prod-vault' } });
        fireEvent.change(screen.getByLabelText('Role ID'), { target: { value: '3' } });
        fireEvent.click(screen.getByRole('button', { name: /Add grant/i }));
        expect(createGrantMutate).toHaveBeenCalledWith(
            { roleId: 3, connector: 'prod-vault', refPrefix: '' },
            expect.anything()
        );
    });

    it('shows a spinner and disables Add grant while a grant is being created', () => {
        createGrantState = { isPending: true };
        render(<KeyorixConnectPage />);
        const submit = screen.getByRole('button', { name: /Add grant/i });
        expect(submit).toBeDisabled();
        expect(submit.querySelector('svg.animate-spin')).toBeInTheDocument();
    });

    it('handles an undefined connectors list in the grants panel', () => {
        connectorsState = { data: undefined as unknown as string[], isLoading: false, isError: false };
        render(<KeyorixConnectPage />);
        expect(screen.getByText(/No connectors are configured/i)).toBeInTheDocument();
        expect(screen.getByLabelText('Connector')).toBeInTheDocument();
    });
});

describe('KeyorixConnectPage — federated read panel additional coverage', () => {
    it('shows a loading spinner while connectors load', () => {
        connectorsState = { data: [], isLoading: true, isError: false };
        const { container } = render(<KeyorixConnectPage />);
        expect(container.querySelector('svg.animate-spin')).toBeInTheDocument();
    });

    it('shows an error message when connectors fail to load', () => {
        connectorsState = { data: [], isLoading: false, isError: true };
        render(<KeyorixConnectPage />);
        expect(screen.getByText('Could not load connectors')).toBeInTheDocument();
    });

    it('reads from an explicitly selected connector', () => {
        render(<KeyorixConnectPage />);
        fireEvent.change(screen.getAllByLabelText('Connector')[0], { target: { value: 'prod-vault' } });
        fireEvent.change(screen.getByLabelText('Reference'), { target: { value: 'prod/db' } });
        fireEvent.click(screen.getByRole('button', { name: /Read secret/i }));
        expect(readMutate).toHaveBeenCalledWith({ connector: 'prod-vault', ref: 'prod/db' }, expect.anything());
    });

    it('falls back to the Error message when a read error has no response message', () => {
        readMutate.mockImplementation((_vars, opts) => opts.onError(new Error('read boom')));
        render(<KeyorixConnectPage />);
        fireEvent.change(screen.getByLabelText('Reference'), { target: { value: 'x' } });
        fireEvent.click(screen.getByRole('button', { name: /Read secret/i }));
        expect(screen.getByText('read boom')).toBeInTheDocument();
    });

    it('falls back to a generic message when a read error has neither a response nor a message', () => {
        readMutate.mockImplementation((_vars, opts) => opts.onError({}));
        render(<KeyorixConnectPage />);
        fireEvent.change(screen.getByLabelText('Reference'), { target: { value: 'x' } });
        fireEvent.click(screen.getByRole('button', { name: /Read secret/i }));
        expect(screen.getByText('Read failed.')).toBeInTheDocument();
    });

    it('shows a spinner and disables Read secret while a read is pending', () => {
        readState = { isPending: true };
        render(<KeyorixConnectPage />);
        fireEvent.change(screen.getByLabelText('Reference'), { target: { value: 'x' } });
        const submit = screen.getByRole('button', { name: /Read secret/i });
        expect(submit).toBeDisabled();
        expect(submit.querySelector('svg.animate-spin')).toBeInTheDocument();
    });

    it('copies the revealed value and flips the icon', async () => {
        readMutate.mockImplementation((_vars, opts) =>
            opts.onSuccess({ connector: 'prod-aws', ref: 'prod/db', value: 's3cr3t' })
        );
        render(<KeyorixConnectPage />);
        fireEvent.change(screen.getByLabelText('Reference'), { target: { value: 'prod/db' } });
        fireEvent.click(screen.getByRole('button', { name: /Read secret/i }));

        const copyButton = screen.getByRole('button', { name: 'Copy value' });
        const before = copyButton.innerHTML;
        fireEvent.click(copyButton);
        await waitFor(() => expect(navigator.clipboard.writeText).toHaveBeenCalledWith('s3cr3t'));
        await waitFor(() => expect(copyButton.innerHTML).not.toBe(before));
    });

    // G28: the revealed value must not linger indefinitely with no explicit Hide.
    describe('auto-clear (G28)', () => {
        afterEach(() => {
            vi.useRealTimers();
        });

        it('re-masks the revealed value after the idle timeout elapses, without an explicit Hide click', async () => {
            readMutate.mockImplementation((_vars, opts) =>
                opts.onSuccess({ connector: 'prod-aws', ref: 'prod/db', value: 'idle-s3cr3t' })
            );
            // Fake timers must be active from mount so the idle timer the hook
            // arms on mount is itself a fake timer (enabling fake timers *after*
            // mount would leave that already-armed real setTimeout untouched).
            vi.useFakeTimers();

            render(<KeyorixConnectPage />);
            fireEvent.change(screen.getByLabelText('Reference'), { target: { value: 'prod/db' } });
            fireEvent.click(screen.getByRole('button', { name: /Read secret/i }));
            fireEvent.click(screen.getByRole('button', { name: /Reveal value/i }));
            // The mock's onSuccess runs synchronously, so the reveal is already
            // flushed here — assert directly rather than via waitFor (whose own
            // polling uses real timers, which freeze once fake timers are active).
            expect(screen.getByText('idle-s3cr3t')).toBeInTheDocument();

            await act(async () => {
                await vi.advanceTimersByTimeAsync(DEFAULT_SENSITIVE_IDLE_MS);
            });

            expect(screen.queryByText('idle-s3cr3t')).not.toBeInTheDocument();
            expect(screen.getByRole('button', { name: /Reveal value/i })).toBeInTheDocument();
        });

        it('re-masks the revealed value when the tab is backgrounded, without an explicit Hide click', async () => {
            readMutate.mockImplementation((_vars, opts) =>
                opts.onSuccess({ connector: 'prod-aws', ref: 'prod/db', value: 'bg-s3cr3t' })
            );

            render(<KeyorixConnectPage />);
            fireEvent.change(screen.getByLabelText('Reference'), { target: { value: 'prod/db' } });
            fireEvent.click(screen.getByRole('button', { name: /Read secret/i }));
            fireEvent.click(screen.getByRole('button', { name: /Reveal value/i }));
            await waitFor(() => expect(screen.getByText('bg-s3cr3t')).toBeInTheDocument());

            Object.defineProperty(document, 'visibilityState', { value: 'hidden', configurable: true });
            act(() => {
                document.dispatchEvent(new Event('visibilitychange'));
            });

            expect(screen.queryByText('bg-s3cr3t')).not.toBeInTheDocument();
            expect(screen.getByRole('button', { name: /Reveal value/i })).toBeInTheDocument();

            Object.defineProperty(document, 'visibilityState', { value: 'visible', configurable: true });
        });
    });
});
