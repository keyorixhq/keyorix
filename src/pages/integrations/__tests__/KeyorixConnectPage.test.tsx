import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '../../../test/test-utils';
import { KeyorixConnectPage } from '../KeyorixConnectPage';

let connectorsData: string[];
let connectorsState: { data: string[]; isLoading: boolean; isError: boolean };
const readMutate = vi.fn();

vi.mock('../../../features/connect', () => ({
    useConnectors: () => connectorsState,
    useReadFederatedSecret: () => ({ mutate: readMutate, isPending: false }),
}));

beforeEach(() => {
    connectorsData = ['prod-aws', 'prod-vault'];
    connectorsState = { data: connectorsData, isLoading: false, isError: false };
    readMutate.mockReset();
});

describe('KeyorixConnectPage', () => {
    it('renders the overview and configured connectors', () => {
        render(<KeyorixConnectPage />);
        expect(screen.getByText('Keyorix Connect')).toBeInTheDocument();
        expect(screen.getByText('Read a federated secret')).toBeInTheDocument();
        const select = screen.getByLabelText('Connector') as HTMLSelectElement;
        expect(select).toBeInTheDocument();
        expect(screen.getByRole('option', { name: 'prod-aws' })).toBeInTheDocument();
        expect(screen.getByRole('option', { name: 'prod-vault' })).toBeInTheDocument();
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
        // Reveal it (the eye toggle is the first outline button in the value box).
        const toggles = screen.getAllByRole('button');
        fireEvent.click(toggles[toggles.length - 2]); // reveal toggle (before copy)
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
