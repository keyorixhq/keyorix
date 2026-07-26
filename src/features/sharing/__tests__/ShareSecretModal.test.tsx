import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '../../../test/test-utils';
import { ShareSecretModal, expiresAtFromPreset } from '../ShareSecretModal';
import { Secret } from '../../../types';

const mockMutate = vi.fn();

vi.mock('../api', () => ({
    useShareSecret: () => ({
        mutate: mockMutate,
        reset: vi.fn(),
        isPending: false,
        isError: false,
        error: null,
    }),
}));

// The modal searches users by query before a recipient can be selected.
vi.mock('../../../services/users', () => ({
    usersApi: {
        list: vi.fn(async () => ({
            users: [{ id: 7, username: 'bob', display_name: 'Bob', email: 'bob@test.com' }],
        })),
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
