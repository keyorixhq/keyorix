import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '../../../test/test-utils';
import { Header } from '../Header';
import { useAuth } from '../../../features/auth';
import { useUIStore } from '../../../store/uiStore';
import { ROUTES } from '../../../constants';

// Header composes NotificationBell directly (../../features/notifications), which
// already has its own dedicated test suite (src/features/notifications/__tests__/
// NotificationBell.test.tsx). Stub it here so this file stays focused on Header's
// own composition/wiring rather than re-testing the bell's internals.
vi.mock('../../../features/notifications', () => ({
    NotificationBell: () => <div>notification bell stub</div>,
}));

const { navigateMock, logoutMock } = vi.hoisted(() => ({
    navigateMock: vi.fn(),
    logoutMock: vi.fn(),
}));

vi.mock('react-router', async (importOriginal) => {
    const actual = (await importOriginal()) as object;
    return { ...actual, useNavigate: () => navigateMock };
});

vi.mock('../../../features/auth', () => ({
    useAuth: vi.fn(),
}));

const mockUseAuth = vi.mocked(useAuth);

type MockUser = {
    displayName?: string;
    username?: string;
    email?: string;
    roles?: string[];
    pendingSteps?: string[];
} | null;

function setUser(user: MockUser) {
    mockUseAuth.mockReturnValue({
        user,
        logout: logoutMock,
    } as unknown as ReturnType<typeof useAuth>);
}

function openUserMenu() {
    const trigger = screen.getByTestId('user-menu-button');
    // jsdom's Radix DropdownMenu.Trigger only opens on a real pointerdown (the
    // click alone does not flip data-state to "open"), so both events are needed.
    fireEvent.pointerDown(trigger, { pointerId: 1, pointerType: 'mouse', button: 0 });
    fireEvent.click(trigger);
}

function selectMenuItem(name: string) {
    const item = screen.getByText(name);
    fireEvent.pointerDown(item, { pointerId: 1, pointerType: 'mouse', button: 0 });
    fireEvent.pointerUp(item, { pointerId: 1, pointerType: 'mouse', button: 0 });
    fireEvent.click(item);
}

describe('Header', () => {
    const onMenuClick = vi.fn();

    it('shows the notification bell normally, but not under the MFA-enrolment confinement (#3155)', () => {
        setUser({ username: 'janedoe', pendingSteps: ['enroll_mfa'] });
        const confined = render(<Header onMenuClick={onMenuClick} />);
        expect(screen.queryByText('notification bell stub')).toBeNull();
        confined.unmount();

        setUser({ username: 'janedoe' });
        render(<Header onMenuClick={onMenuClick} />);
        expect(screen.getByText('notification bell stub')).toBeInTheDocument();
    });

    beforeEach(() => {
        mockUseAuth.mockReset();
        navigateMock.mockClear();
        logoutMock.mockReset();
        onMenuClick.mockClear();
        // Real uiStore per house convention (store actions are referentially
        // stable) — reset to the store's own default theme between tests.
        useUIStore.setState({ theme: 'dark' });
        setUser({ displayName: 'Jane Doe', username: 'janedoe', email: 'jane@example.com', roles: ['admin'] });
    });

    it('renders the mobile sidebar toggle and calls onMenuClick', () => {
        render(<Header onMenuClick={onMenuClick} />);
        fireEvent.click(screen.getByRole('button', { name: /open sidebar/i }));
        expect(onMenuClick).toHaveBeenCalledTimes(1);
    });

    it('composes the notification bell', () => {
        render(<Header onMenuClick={onMenuClick} />);
        expect(screen.getByText('notification bell stub')).toBeInTheDocument();
    });

    it('applies the className prop to the header element', () => {
        const { container } = render(<Header onMenuClick={onMenuClick} className="custom-header" />);
        expect(container.querySelector('header')).toHaveClass('custom-header');
    });

    describe('user menu trigger label', () => {
        it('prefers displayName', () => {
            render(<Header onMenuClick={onMenuClick} />);
            expect(screen.getByTestId('user-menu-button')).toHaveTextContent('Jane Doe');
        });

        it('falls back to username when displayName is absent', () => {
            setUser({ username: 'janedoe' });
            render(<Header onMenuClick={onMenuClick} />);
            expect(screen.getByTestId('user-menu-button')).toHaveTextContent('janedoe');
        });

        it('falls back to "User" when there is no user', () => {
            setUser(null);
            render(<Header onMenuClick={onMenuClick} />);
            expect(screen.getByTestId('user-menu-button')).toHaveTextContent('User');
        });
    });

    describe('user menu actions', () => {
        it('opens and shows the My Account / Sign out items', () => {
            render(<Header onMenuClick={onMenuClick} />);
            openUserMenu();
            expect(screen.getByText('My Account')).toBeInTheDocument();
            expect(screen.getByText('Sign out')).toBeInTheDocument();
        });

        it('navigates to the profile route from My Account', () => {
            render(<Header onMenuClick={onMenuClick} />);
            openUserMenu();
            selectMenuItem('My Account');
            expect(navigateMock).toHaveBeenCalledWith(ROUTES.PROFILE);
        });

        it('calls the real logout action then redirects to /login on Sign out', async () => {
            logoutMock.mockResolvedValue(undefined);
            render(<Header onMenuClick={onMenuClick} />);
            openUserMenu();
            selectMenuItem('Sign out');
            expect(logoutMock).toHaveBeenCalledTimes(1);
            await waitFor(() => expect(navigateMock).toHaveBeenCalledWith('/login'));
        });

        // Documents existing behavior, not a fix: if logout() rejects, Header only
        // logs the error to the console and leaves the user on the current page —
        // there is no user-facing error surfaced from the header itself.
        it('swallows a failed logout into console.error without navigating', async () => {
            const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
            logoutMock.mockRejectedValue(new Error('network down'));
            render(<Header onMenuClick={onMenuClick} />);
            openUserMenu();
            selectMenuItem('Sign out');
            await waitFor(() => expect(consoleErrorSpy).toHaveBeenCalledWith('Logout failed:', expect.any(Error)));
            expect(navigateMock).not.toHaveBeenCalledWith('/login');
            consoleErrorSpy.mockRestore();
        });
    });

    describe('theme switch', () => {
        it('shows all three positions at once and marks the current one', () => {
            render(<Header onMenuClick={onMenuClick} />);
            const group = screen.getByRole('radiogroup', { name: 'Theme' });
            const radios = Array.from(group.querySelectorAll('[role="radio"]'));
            expect(radios.map((r) => r.getAttribute('aria-label'))).toEqual(['Light', 'Match system', 'Dark']);
            expect(screen.getByRole('radio', { name: 'Dark' })).toHaveAttribute('aria-checked', 'true');
            expect(screen.getByRole('radio', { name: 'Light' })).toHaveAttribute('aria-checked', 'false');
            expect(screen.getByRole('radio', { name: 'Match system' })).toHaveAttribute('aria-checked', 'false');
        });

        it('sets each theme directly in the real uiStore, in any order', () => {
            render(<Header onMenuClick={onMenuClick} />);
            fireEvent.click(screen.getByRole('radio', { name: 'Light' }));
            expect(useUIStore.getState().theme).toBe('light');
            expect(screen.getByRole('radio', { name: 'Light' })).toHaveAttribute('aria-checked', 'true');

            fireEvent.click(screen.getByRole('radio', { name: 'Match system' }));
            expect(useUIStore.getState().theme).toBe('system');

            fireEvent.click(screen.getByRole('radio', { name: 'Dark' }));
            expect(useUIStore.getState().theme).toBe('dark');
        });

        it('has one tab stop (the selected option) and moves with the arrow keys', () => {
            render(<Header onMenuClick={onMenuClick} />);
            expect(screen.getByRole('radio', { name: 'Dark' })).toHaveAttribute('tabindex', '0');
            expect(screen.getByRole('radio', { name: 'Light' })).toHaveAttribute('tabindex', '-1');

            fireEvent.keyDown(screen.getByRole('radio', { name: 'Dark' }), { key: 'ArrowRight' });
            expect(useUIStore.getState().theme).toBe('light'); // wraps from the last to the first
            fireEvent.keyDown(screen.getByRole('radio', { name: 'Light' }), { key: 'ArrowRight' });
            expect(useUIStore.getState().theme).toBe('system');
            fireEvent.keyDown(screen.getByRole('radio', { name: 'Match system' }), { key: 'ArrowLeft' });
            expect(useUIStore.getState().theme).toBe('light');
        });
    });

    describe('settings button', () => {
        it('is visible in the header, named for screen readers, and opens the settings page', () => {
            render(<Header onMenuClick={onMenuClick} />);
            const button = screen.getByRole('button', { name: 'Settings' });
            expect(button).toHaveAttribute('title', 'Settings');
            fireEvent.click(button);
            expect(navigateMock).toHaveBeenCalledWith(ROUTES.SETTINGS_APPEARANCE);
        });
    });
});
