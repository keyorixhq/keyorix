import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '../../../test/test-utils';
import { ShareSecretModal, expiresAtFromPreset } from '../ShareSecretModal';
import { Secret } from '../../../types';

const mockMutate = vi.fn();
const mockReset = vi.fn();
let isPending = false;
let isError = false;
let mutationError: unknown = null;

vi.mock('../api', () => ({
    useShareSecret: () => ({
        mutate: mockMutate,
        reset: mockReset,
        isPending,
        isError,
        error: mutationError,
    }),
}));

// The modal searches users by query before a recipient can be selected. `searchImpl` is
// reassigned per-test (rather than using mockResolvedValueOnce/mockRejectedValueOnce)
// so a stray call from a previous test's not-yet-unmounted debounce timer can never
// consume a queued response meant for the current test.
let searchImpl: (args: { search: string; pageSize: number }) => Promise<{ users: unknown[] }> = async () => ({
    users: [{ id: 7, username: 'bob', display_name: 'Bob', email: 'bob@test.com' }],
});

// The modal searches users by query before a recipient can be selected.
vi.mock('../../../services/users', () => ({
    usersApi: {
        list: (...args: [{ search: string; pageSize: number }]) => searchImpl(...args),
    },
}));

const secret: Secret = {
    id: 1,
    name: 'db-password',
    type: 'password',
    environment: 'production',
    isShared: false,
    shareCount: 0,
    lastModified: '2026-06-17T00:00:00Z',
    owner: 'alice',
    permissions: [],
    metadata: {},
    tags: [],
    classification: 'confidential',
};

beforeEach(() => {
    isPending = false;
    isError = false;
    mutationError = null;
    mockMutate.mockReset();
    mockReset.mockReset();
    searchImpl = async () => ({
        users: [{ id: 7, username: 'bob', display_name: 'Bob', email: 'bob@test.com' }],
    });
});

describe('expiresAtFromPreset', () => {
    const base = Date.UTC(2026, 5, 17, 12, 0, 0); // 2026-06-17T12:00:00Z

    it('returns undefined for a permanent share', () => {
        expect(expiresAtFromPreset('never', base)).toBeUndefined();
        expect(expiresAtFromPreset('bogus', base)).toBeUndefined();
    });

    it('resolves presets to an ISO timestamp in the future', () => {
        expect(expiresAtFromPreset('1h', base)).toBe('2026-06-17T13:00:00.000Z');
        expect(expiresAtFromPreset('24h', base)).toBe('2026-06-18T12:00:00.000Z');
        expect(expiresAtFromPreset('7d', base)).toBe('2026-06-24T12:00:00.000Z');
    });
});

describe('ShareSecretModal expiry', () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    it('shares with no expiresAt when expiry is "Never"', async () => {
        render(<ShareSecretModal secret={secret} isOpen onClose={() => {}} />);
        fireEvent.change(screen.getByPlaceholderText(/Search by name/i), { target: { value: 'bob' } });
        fireEvent.click(await screen.findByText('Bob'));
        fireEvent.click(screen.getByRole('button', { name: /^Share$/i }));

        await waitFor(() => expect(mockMutate).toHaveBeenCalled());
        const [payload] = mockMutate.mock.calls[0];
        expect(payload.username).toBe('bob');
        expect(payload.expiresAt).toBeUndefined();
    });

    it('passes an ISO expiresAt when a duration preset is chosen', async () => {
        render(<ShareSecretModal secret={secret} isOpen onClose={() => {}} />);
        fireEvent.change(screen.getByPlaceholderText(/Search by name/i), { target: { value: 'bob' } });
        fireEvent.click(await screen.findByText('Bob'));
        fireEvent.change(screen.getByDisplayValue('Never (permanent)'), { target: { value: '24h' } });
        fireEvent.click(screen.getByRole('button', { name: /^Share$/i }));

        await waitFor(() => expect(mockMutate).toHaveBeenCalled());
        const [payload] = mockMutate.mock.calls[0];
        expect(payload.expiresAt).toMatch(/^\d{4}-\d{2}-\d{2}T/); // a real ISO timestamp
        expect(new Date(payload.expiresAt).getTime()).toBeGreaterThan(Date.now());
    });
});

describe('ShareSecretModal recipient search', () => {
    it('shows "Searching…" while the query is in flight, then the results', async () => {
        let resolveUsers: (v: { users: unknown[] }) => void = () => {};
        searchImpl = () =>
            new Promise((resolve) => {
                resolveUsers = resolve;
            });

        render(<ShareSecretModal secret={secret} isOpen onClose={() => {}} />);
        fireEvent.change(screen.getByPlaceholderText(/Search by name/i), { target: { value: 'bo' } });

        expect(await screen.findByText('Searching…')).toBeInTheDocument();
        resolveUsers({ users: [{ id: 7, username: 'bob', display_name: 'Bob', email: 'bob@test.com' }] });
        expect(await screen.findByText('Bob')).toBeInTheDocument();
    });

    it('clears results and stops loading when the user search rejects', async () => {
        searchImpl = async () => {
            throw new Error('network down');
        };

        render(<ShareSecretModal secret={secret} isOpen onClose={() => {}} />);
        fireEvent.change(screen.getByPlaceholderText(/Search by name/i), { target: { value: 'bob' } });

        expect(await screen.findByText(/No users found/)).toBeInTheDocument();
    });

    it('falls back to username when a matched user has no display name', async () => {
        searchImpl = async () => ({
            users: [{ id: 8, username: 'nodisplay', display_name: '', email: 'nd@test.com' }],
        });

        render(<ShareSecretModal secret={secret} isOpen onClose={() => {}} />);
        fireEvent.change(screen.getByPlaceholderText(/Search by name/i), { target: { value: 'nod' } });
        fireEvent.click(await screen.findByText('nodisplay'));

        expect((screen.getByPlaceholderText(/Search by name/i) as HTMLInputElement).value).toBe('nodisplay');
    });

    it('applies hover style handlers on a dropdown option', async () => {
        render(<ShareSecretModal secret={secret} isOpen onClose={() => {}} />);
        fireEvent.change(screen.getByPlaceholderText(/Search by name/i), { target: { value: 'bob' } });
        const option = await screen.findByText('Bob');
        const button = option.closest('button') as HTMLButtonElement;

        fireEvent.mouseEnter(button);
        expect(button.style.backgroundColor).toBeTruthy();
        fireEvent.mouseLeave(button);
        expect(button.style.backgroundColor).toBe('');
    });

    it('closes the dropdown on an outside click', async () => {
        render(<ShareSecretModal secret={secret} isOpen onClose={() => {}} />);
        fireEvent.change(screen.getByPlaceholderText(/Search by name/i), { target: { value: 'bob' } });
        await screen.findByText('Bob');

        fireEvent.mouseDown(document.body);
        expect(screen.queryByText('Bob')).not.toBeInTheDocument();
    });

    it('reopens the dropdown on focus when a query is already present', async () => {
        render(<ShareSecretModal secret={secret} isOpen onClose={() => {}} />);
        const input = screen.getByPlaceholderText(/Search by name/i);
        fireEvent.change(input, { target: { value: 'bob' } });
        fireEvent.click(await screen.findByText('Bob'));
        expect(screen.queryByText('Bob')).not.toBeInTheDocument();

        fireEvent.focus(input);
        expect(await screen.findByText('Bob')).toBeInTheDocument();
    });
});

describe('ShareSecretModal submission + lifecycle', () => {
    it('does nothing on submit when no recipient is selected yet', () => {
        render(<ShareSecretModal secret={secret} isOpen onClose={() => {}} />);
        // The Modal renders its content through a portal, so query the document rather
        // than the render container.
        const form = document.querySelector('form') as HTMLFormElement;
        fireEvent.submit(form);
        expect(mockMutate).not.toHaveBeenCalled();
    });

    it('Cancel resets all fields, the mutation, and closes the modal', () => {
        const onClose = vi.fn();
        render(<ShareSecretModal secret={secret} isOpen onClose={onClose} />);
        fireEvent.change(screen.getByPlaceholderText(/Search by name/i), { target: { value: 'bob' } });
        fireEvent.click(screen.getByRole('button', { name: /^Cancel$/i }));

        expect(mockReset).toHaveBeenCalled();
        expect(onClose).toHaveBeenCalled();
    });

    it('changes the permission and includes it in the share payload', async () => {
        render(<ShareSecretModal secret={secret} isOpen onClose={() => {}} />);
        fireEvent.change(screen.getByPlaceholderText(/Search by name/i), { target: { value: 'bob' } });
        fireEvent.click(await screen.findByText('Bob'));
        fireEvent.change(screen.getByDisplayValue('Read Only'), { target: { value: 'write' } });
        fireEvent.click(screen.getByRole('button', { name: /^Share$/i }));

        await waitFor(() => expect(mockMutate).toHaveBeenCalled());
        const [payload] = mockMutate.mock.calls[0];
        expect(payload.permission).toBe('write');
    });

    it('shows a success message, calls onSuccess, and auto-closes after a delay', async () => {
        mockMutate.mockImplementation((_vars: unknown, opts: { onSuccess: () => void }) => opts.onSuccess());
        const onSuccessCb = vi.fn();
        const onCloseCb = vi.fn();

        render(<ShareSecretModal secret={secret} isOpen onClose={onCloseCb} onSuccess={onSuccessCb} />);
        fireEvent.change(screen.getByPlaceholderText(/Search by name/i), { target: { value: 'bob' } });
        fireEvent.click(await screen.findByText('Bob'));
        fireEvent.click(screen.getByRole('button', { name: /^Share$/i }));

        expect(screen.getByText('Shared!')).toBeInTheDocument();
        expect(onSuccessCb).toHaveBeenCalled();

        await waitFor(() => expect(onCloseCb).toHaveBeenCalled(), { timeout: 2000 });
    });

    it('shows the Error message when the mutation fails with an Error instance', () => {
        isError = true;
        mutationError = new Error('Username not found');
        render(<ShareSecretModal secret={secret} isOpen onClose={() => {}} />);
        expect(screen.getByText('Username not found')).toBeInTheDocument();
    });

    it('shows a fallback message when the mutation fails with a non-Error value', () => {
        isError = true;
        mutationError = { code: 'ERR' };
        render(<ShareSecretModal secret={secret} isOpen onClose={() => {}} />);
        expect(screen.getByText('Failed to share secret.')).toBeInTheDocument();
    });

    it('shows "Sharing…" and disables the search input while the mutation is pending', () => {
        isPending = true;
        render(<ShareSecretModal secret={secret} isOpen onClose={() => {}} />);
        expect(screen.getByRole('button', { name: 'Sharing…' })).toBeInTheDocument();
        expect(screen.getByPlaceholderText(/Search by name/i)).toBeDisabled();
    });
});
