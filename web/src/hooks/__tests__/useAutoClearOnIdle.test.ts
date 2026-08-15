import { describe, it, expect, vi, afterEach } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import { useAutoClearOnIdle, DEFAULT_SENSITIVE_IDLE_MS } from '../useAutoClearOnIdle';

afterEach(() => {
    vi.useRealTimers();
    // Restore visibilityState between tests since some tests stub it.
    Object.defineProperty(document, 'visibilityState', { value: 'visible', configurable: true });
});

describe('useAutoClearOnIdle', () => {
    it('calls onClear after idleMs of inactivity while active', async () => {
        vi.useFakeTimers();
        const onClear = vi.fn();
        renderHook(() => useAutoClearOnIdle(onClear, true, 1000));

        await act(async () => {
            await vi.advanceTimersByTimeAsync(999);
        });
        expect(onClear).not.toHaveBeenCalled();

        await act(async () => {
            await vi.advanceTimersByTimeAsync(1);
        });
        expect(onClear).toHaveBeenCalledTimes(1);
    });

    it('uses DEFAULT_SENSITIVE_IDLE_MS (1 minute) when no idleMs is given', async () => {
        vi.useFakeTimers();
        const onClear = vi.fn();
        renderHook(() => useAutoClearOnIdle(onClear, true));

        await act(async () => {
            await vi.advanceTimersByTimeAsync(DEFAULT_SENSITIVE_IDLE_MS - 1);
        });
        expect(onClear).not.toHaveBeenCalled();

        await act(async () => {
            await vi.advanceTimersByTimeAsync(1);
        });
        expect(onClear).toHaveBeenCalledTimes(1);
    });

    it('resets the idle timer on activity (e.g. mousemove), so it does not fire early', async () => {
        vi.useFakeTimers();
        const onClear = vi.fn();
        renderHook(() => useAutoClearOnIdle(onClear, true, 1000));

        await act(async () => {
            await vi.advanceTimersByTimeAsync(700);
        });
        act(() => {
            window.dispatchEvent(new Event('mousemove'));
        });
        await act(async () => {
            await vi.advanceTimersByTimeAsync(700);
        });
        // 1400ms of elapsed time, but activity at 700ms reset the 1000ms window.
        expect(onClear).not.toHaveBeenCalled();

        await act(async () => {
            await vi.advanceTimersByTimeAsync(300);
        });
        expect(onClear).toHaveBeenCalledTimes(1);
    });

    it('calls onClear immediately when the tab is backgrounded (visibilitychange to hidden)', () => {
        const onClear = vi.fn();
        renderHook(() => useAutoClearOnIdle(onClear, true, 60_000));

        Object.defineProperty(document, 'visibilityState', { value: 'hidden', configurable: true });
        act(() => {
            document.dispatchEvent(new Event('visibilitychange'));
        });

        expect(onClear).toHaveBeenCalledTimes(1);
    });

    it('does not call onClear on visibilitychange when the tab becomes visible', () => {
        const onClear = vi.fn();
        renderHook(() => useAutoClearOnIdle(onClear, true, 60_000));

        Object.defineProperty(document, 'visibilityState', { value: 'visible', configurable: true });
        act(() => {
            document.dispatchEvent(new Event('visibilitychange'));
        });

        expect(onClear).not.toHaveBeenCalled();
    });

    it('calls onClear immediately on window blur', () => {
        const onClear = vi.fn();
        renderHook(() => useAutoClearOnIdle(onClear, true, 60_000));

        act(() => {
            window.dispatchEvent(new Event('blur'));
        });

        expect(onClear).toHaveBeenCalledTimes(1);
    });

    it('does nothing while inactive: no timers armed, no listeners firing onClear', async () => {
        vi.useFakeTimers();
        const onClear = vi.fn();
        renderHook(() => useAutoClearOnIdle(onClear, false, 1000));

        await act(async () => {
            await vi.advanceTimersByTimeAsync(5000);
        });
        act(() => {
            window.dispatchEvent(new Event('blur'));
        });
        Object.defineProperty(document, 'visibilityState', { value: 'hidden', configurable: true });
        act(() => {
            document.dispatchEvent(new Event('visibilitychange'));
        });

        expect(onClear).not.toHaveBeenCalled();
    });

    it('tears down its listeners once active flips back to false, so a later idle/blur does not fire', async () => {
        vi.useFakeTimers();
        const onClear = vi.fn();
        const { rerender } = renderHook(
            ({ active }: { active: boolean }) => useAutoClearOnIdle(onClear, active, 1000),
            {
                initialProps: { active: true },
            }
        );

        rerender({ active: false });

        await act(async () => {
            await vi.advanceTimersByTimeAsync(5000);
        });
        act(() => {
            window.dispatchEvent(new Event('blur'));
        });

        expect(onClear).not.toHaveBeenCalled();
    });

    it('always calls the latest onClear, even if it changed after the timer/listeners were armed', async () => {
        vi.useFakeTimers();
        const first = vi.fn();
        const second = vi.fn();
        const { rerender } = renderHook(
            ({ onClear }: { onClear: () => void }) => useAutoClearOnIdle(onClear, true, 1000),
            {
                initialProps: { onClear: first },
            }
        );

        rerender({ onClear: second });

        await act(async () => {
            await vi.advanceTimersByTimeAsync(1000);
        });

        expect(first).not.toHaveBeenCalled();
        expect(second).toHaveBeenCalledTimes(1);
    });

    it('cleans up its timer and listeners on unmount, without throwing', async () => {
        vi.useFakeTimers();
        const onClear = vi.fn();
        const { unmount } = renderHook(() => useAutoClearOnIdle(onClear, true, 1000));

        expect(() => unmount()).not.toThrow();

        await act(async () => {
            await vi.advanceTimersByTimeAsync(5000);
        });
        expect(onClear).not.toHaveBeenCalled();
    });
});
