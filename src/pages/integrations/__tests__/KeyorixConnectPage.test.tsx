import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '../../../test/test-utils';
import { KeyorixConnectPage } from '../KeyorixConnectPage';

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

vi.mock('../../../features/connect', () => ({
    useConnectors: () => connectorsState,
    useReadFederatedSecret: () => ({ mutate: readMutate, isPending: false }),
    useRefGrants: () => grantsState,
    useCreateRefGrant: () => ({ mutate: createGrantMutate, isPending: false }),
    useDeleteRefGrant: () => ({ mutate: deleteGrantMutate, isPending: false }),
}));

beforeEach(() => {
    connectorsData = ['prod-aws', 'prod-vault'];
    connectorsState = { data: connectorsData, isLoading: false, isError: false };
    grantsState = { data: [], isLoading: false, isError: false };
    readMutate.mockReset();
    createGrantMutate.mockReset();
    deleteGrantMutate.mockReset();
});

describe('KeyorixConnectPage', () => {
    it('renders the overview and configured connectors', () => {
        render(<KeyorixConnectPage />);
        expect(screen.getByText('Keyorix Connect')).toBeInTheDocument();
        expect(screen.getByText('Read a federated secret')).toBeInTheDocument();
        const select = screen.getByLabelText('Connector') as HTMLSelectElement;
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
        readMutate.mockImplementation((_vars, opts) => opts.onSuccess({ connector: 'prod-aws', ref: 'prod/db', value: 's3cr3t' }));
        render(<KeyorixConnectPage />);

        fireEvent.change(screen.getByLabelText('Reference'), { target: { value: 'prod/db' } });
        fireEvent.click(screen.getByRole('button', { name: /Read secret/i }));

        expect(readMutate).toHaveBeenCalledWith(
            { connector: 'prod-aws', ref: 'prod/db' },
            expect.anything(),
        );
        // Value is masked until revealed.
        expect(screen.queryByText('s3cr3t')).not.toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: /Reveal value/i }));
        await waitFor(() => expect(screen.getByText('s3cr3t')).toBeInTheDocument());
    });

    it('surfaces a read error', () => {
        readMutate.mockImplementation((_vars, opts) =>
            opts.onError({ response: { data: { message: 'ref not permitted' } } }),
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
            expect.anything(),
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
});
