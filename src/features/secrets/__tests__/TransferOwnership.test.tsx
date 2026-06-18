import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '../../../test/test-utils';
import { TransferOwnership } from '../TransferOwnership';

const mockMutate = vi.fn();

vi.mock('../api', () => ({
    useTransferOwnership: () => ({ mutate: mockMutate, reset: vi.fn(), isPending: false, isError: false, error: null }),
}));

vi.mock('../../../services/users', () => ({
    usersApi: {
        search: vi.fn(async () => [
            { id: 5, name: 'alice', type: 'user', email: 'alice@test.com' },
            { id: 6, name: 'devs', type: 'group' }, // groups must be filtered out
        ]),
    },
}));

describe('TransferOwnership', () => {
    beforeEach(() => { vi.clearAllMocks(); });

    it('is collapsed by default, showing a trigger', () => {
        render(<TransferOwnership secretId={1} currentOwner="bob" />);
        expect(screen.getByText('Transfer ownership')).toBeInTheDocument();
        expect(screen.queryByPlaceholderText(/Search by name/i)).not.toBeInTheDocument();
    });

    it('searches users (excluding groups) and transfers to the chosen one', async () => {
        const confirmSpy = vi.spyOn(window, 'confirm').mockReturnValue(true);
        render(<TransferOwnership secretId={1} currentOwner="bob" />);

        fireEvent.click(screen.getByText('Transfer ownership'));
        fireEvent.change(screen.getByPlaceholderText(/Search by name/i), { target: { value: 'a' } });

        // alice (user) appears; devs (group) is filtered out.
        const alice = await screen.findByText(/alice/);
        expect(screen.queryByText(/devs/)).not.toBeInTheDocument();

        fireEvent.click(alice);
        fireEvent.click(screen.getByRole('button', { name: /^Transfer$/i }));

        await waitFor(() => expect(mockMutate).toHaveBeenCalled());
        expect(mockMutate.mock.calls[0][0]).toBe(5); // new owner id
        confirmSpy.mockRestore();
    });

    it('does not transfer when the confirm is declined', async () => {
        const confirmSpy = vi.spyOn(window, 'confirm').mockReturnValue(false);
        render(<TransferOwnership secretId={1} currentOwner="bob" />);
        fireEvent.click(screen.getByText('Transfer ownership'));
        fireEvent.change(screen.getByPlaceholderText(/Search by name/i), { target: { value: 'a' } });
        fireEvent.click(await screen.findByText(/alice/));
        fireEvent.click(screen.getByRole('button', { name: /^Transfer$/i }));
        expect(mockMutate).not.toHaveBeenCalled();
        confirmSpy.mockRestore();
    });
});
