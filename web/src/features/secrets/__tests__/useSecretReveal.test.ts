import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { act, renderHook, waitFor } from '@testing-library/react';
import { useSecretReveal } from '../useSecretReveal';
import { Secret } from '../../../types';

const { getVersionsMock, copyToClipboardMock } = vi.hoisted(() => ({
    getVersionsMock: vi.fn(),
    copyToClipboardMock: vi.fn(),
}));

vi.mock('../../../services/secrets', () => ({
    secretsApi: {
        getVersions: getVersionsMock,
    },
}));

vi.mock('../../../utils', () => ({
    copyToClipboard: copyToClipboardMock,
}));

const makeSecret = (overrides: Partial<Secret> = {}): Secret => ({
    id: 1,
    name: 'db-password',
    type: 'password',
    environment: 'production',
    isShared: false,
    shareCount: 0,
    lastModified: '2026-06-14T00:00:00Z',
    owner: 'alice',
    permissions: [],
    metadata: {},
    tags: [],
    ...overrides,
});

describe('useSecretReveal', () => {
    beforeEach(() => {
        // resetAllMocks (not clearAllMocks) so a mockResolvedValue/mockRejectedValue set in
        // one test can't leak its implementation into the next.
        vi.resetAllMocks();
    });

    afterEach(() => {
        vi.useRealTimers();
    });

    it('copies the decoded value of the first (latest) version and clears copiedSecretId after 2s', async () => {
        vi.useFakeTimers();
        const secret = makeSecret({ id: 42 });
        getVersionsMock.mockResolvedValue([
            { EncryptedValue: btoa('super-secret-value'), VersionNumber: 3, CreatedAt: '2026-06-01T00:00:00Z' },
            { EncryptedValue: btoa('older-value'), VersionNumber: 2, CreatedAt: '2026-05-01T00:00:00Z' },
        ]);
        copyToClipboardMock.mockResolvedValue(undefined);

        const { result } = renderHook(() => useSecretReveal());

        await act(async () => {
            await result.current.handleCopySecretValue(secret);
        });

        expect(getVersionsMock).toHaveBeenCalledWith(42);
        expect(copyToClipboardMock).toHaveBeenCalledWith('super-secret-value');
        expect(result.current.copyingSecretId).toBeNull();
        expect(result.current.copiedSecretId).toBe(42);
        expect(result.current.copyErrorId).toBeNull();

        await act(async () => {
            await vi.advanceTimersByTimeAsync(2000);
        });

        expect(result.current.copiedSecretId).toBeNull();
    });

    it('sets copyErrorId (not copiedSecretId) when no versions are returned, and clears after 2s', async () => {
        vi.useFakeTimers();
        const secret = makeSecret({ id: 7 });
        getVersionsMock.mockResolvedValue([]);

        const { result } = renderHook(() => useSecretReveal());

        await act(async () => {
            await result.current.handleCopySecretValue(secret);
        });

        expect(copyToClipboardMock).not.toHaveBeenCalled();
        expect(result.current.copyErrorId).toBe(7);
        expect(result.current.copiedSecretId).toBeNull();
        expect(result.current.copyingSecretId).toBeNull();

        await act(async () => {
            await vi.advanceTimersByTimeAsync(2000);
        });

        expect(result.current.copyErrorId).toBeNull();
    });

    it('sets copyErrorId when versions is undefined', async () => {
        const secret = makeSecret({ id: 8 });
        getVersionsMock.mockResolvedValue(undefined);

        const { result } = renderHook(() => useSecretReveal());

        await act(async () => {
            await result.current.handleCopySecretValue(secret);
        });

        expect(result.current.copyErrorId).toBe(8);
        expect(result.current.copiedSecretId).toBeNull();
    });

    it('sets copyErrorId when copyToClipboard rejects', async () => {
        const secret = makeSecret({ id: 9 });
        getVersionsMock.mockResolvedValue([
            { EncryptedValue: btoa('value'), VersionNumber: 1, CreatedAt: '2026-06-01T00:00:00Z' },
        ]);
        copyToClipboardMock.mockRejectedValue(new Error('clipboard denied'));

        const { result } = renderHook(() => useSecretReveal());

        await act(async () => {
            await result.current.handleCopySecretValue(secret);
        });

        expect(result.current.copyErrorId).toBe(9);
        expect(result.current.copiedSecretId).toBeNull();
    });

    it('sets copyErrorId when the base64 decode fails (atob throws)', async () => {
        const secret = makeSecret({ id: 10 });
        // Not valid base64 — atob throws a DOMException/InvalidCharacterError.
        getVersionsMock.mockResolvedValue([
            { EncryptedValue: 'not-valid-base64!!', VersionNumber: 1, CreatedAt: '2026-06-01T00:00:00Z' },
        ]);

        const { result } = renderHook(() => useSecretReveal());

        await act(async () => {
            await result.current.handleCopySecretValue(secret);
        });

        expect(copyToClipboardMock).not.toHaveBeenCalled();
        expect(result.current.copyErrorId).toBe(10);
        expect(result.current.copiedSecretId).toBeNull();
    });

    it('sets copyingSecretId synchronously while the request is in flight', async () => {
        const secret = makeSecret({ id: 11 });
        let resolveVersions: (
            value: { EncryptedValue: string; VersionNumber: number; CreatedAt: string }[]
        ) => void = () => {};
        getVersionsMock.mockReturnValue(
            new Promise((resolve) => {
                resolveVersions = resolve;
            })
        );
        copyToClipboardMock.mockResolvedValue(undefined);

        const { result } = renderHook(() => useSecretReveal());

        // Sonar flags this as a redundant act() call, but it isn't: handleCopySecretValue
        // sets copyingSecretId synchronously before its first await, and without this
        // wrapper React 18's act-environment defers that flush past the assertion below
        // (verified: removing the wrapper makes the next expect() read null, not 11).
        act(() => {
            // NOSONAR: not redundant, see comment above
            void result.current.handleCopySecretValue(secret);
        });

        expect(result.current.copyingSecretId).toBe(11);

        resolveVersions([{ EncryptedValue: btoa('value'), VersionNumber: 1, CreatedAt: '2026-06-01T00:00:00Z' }]);

        await waitFor(() => expect(result.current.copyingSecretId).toBeNull());
        expect(result.current.copiedSecretId).toBe(11);
    });
});
