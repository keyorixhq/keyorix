import React from 'react';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, fireEvent, within } from '../../../test/test-utils';
import { Sidebar, Leaf, type SidebarProps } from '../Sidebar';
import { useAuth } from '../../../features/auth';

vi.mock('../../../features/auth', () => ({
    useAuth: vi.fn(),
}));

// Mutable per-test state for the mocked ui store. `toggleSidebarGroupMock`
// mutates this object directly (mirroring what the real zustand store does)
// so tests can assert the resulting expand/collapse behavior by calling
// `rerender` after a click — the mocked hook itself doesn't trigger React
// re-renders on its own, since it isn't real store subscription.
const uiState = vi.hoisted(() => ({
    sidebarExpanded: { secrets: true, access: true, integrations: false, settings: false } as Record<string, boolean>,
}));

const toggleSidebarGroupMock = vi.hoisted(() =>
    vi.fn((id: string) => {
        uiState.sidebarExpanded = { ...uiState.sidebarExpanded, [id]: !uiState.sidebarExpanded[id] };
    })
);

vi.mock('../../../store/uiStore', () => ({
    useUIStore: vi.fn(() => ({
        sidebarExpanded: uiState.sidebarExpanded,
        toggleSidebarGroup: toggleSidebarGroupMock,
    })),
}));

// ProjectSwitcher is its own feature (projects + MRU store) unrelated to Sidebar's
// own responsibilities; stub it so failures/changes there don't leak into this
// file, while still exercising that Sidebar wires `onClose` through as `onNavigate`.
vi.mock('../ProjectSwitcher', () => ({
    ProjectSwitcher: ({ onNavigate }: { onNavigate?: () => void }) => (
        <button type="button" data-testid="project-switcher-stub" onClick={() => onNavigate?.()}>
            ProjectSwitcherStub
        </button>
    ),
}));

const mockUseAuth = vi.mocked(useAuth);

function renderSidebar(overrides: Partial<SidebarProps> = {}) {
    const onClose = overrides.onClose ?? vi.fn();
    const utils = render(
        <Sidebar isOpen={overrides.isOpen ?? false} onClose={onClose} className={overrides.className} />
    );
    return { onClose, ...utils };
}

describe('Sidebar', () => {
    beforeEach(() => {
        window.history.pushState({}, '', '/');
        uiState.sidebarExpanded = { secrets: true, access: true, integrations: false, settings: false };
        toggleSidebarGroupMock.mockClear();
        mockUseAuth.mockReset();
        mockUseAuth.mockReturnValue({ isAdmin: true } as unknown as ReturnType<typeof useAuth>);
    });

    it('renders all top-level nav leaves, group headers, and expanded-by-default group children for an admin user', () => {
        renderSidebar();

        expect(screen.getByRole('link', { name: 'Dashboard' })).toBeInTheDocument();
        expect(screen.getByRole('link', { name: 'Projects' })).toBeInTheDocument();
        expect(screen.getByRole('link', { name: 'Sharing' })).toBeInTheDocument();
        expect(screen.getByRole('link', { name: 'Audit Logs' })).toBeInTheDocument();
        expect(screen.getByRole('link', { name: 'Compliance' })).toBeInTheDocument();
        expect(screen.getByRole('link', { name: 'Roadmap' })).toBeInTheDocument();

        expect(screen.getByRole('button', { name: 'Secrets' })).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Access Control' })).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Integrations' })).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Settings' })).toBeInTheDocument();

        // secrets + access default to expanded
        expect(screen.getByRole('link', { name: 'All Secrets' })).toBeInTheDocument();
        expect(screen.getByRole('link', { name: 'Users' })).toBeInTheDocument();

        // integrations + settings default to collapsed
        expect(screen.queryByRole('link', { name: 'Keyorix Connect' })).not.toBeInTheDocument();
        expect(screen.queryByRole('link', { name: 'Appearance' })).not.toBeInTheDocument();

        expect(screen.getByText('Keyorix v0.1.0')).toBeInTheDocument();
    });

    it('hides the admin-only Access Control group and its children entirely for a non-admin user', () => {
        mockUseAuth.mockReturnValue({ isAdmin: false } as unknown as ReturnType<typeof useAuth>);
        renderSidebar();

        expect(screen.queryByRole('button', { name: 'Access Control' })).not.toBeInTheDocument();
        expect(screen.queryByRole('link', { name: 'Users' })).not.toBeInTheDocument();
        expect(screen.queryByRole('link', { name: 'Roles & Policies' })).not.toBeInTheDocument();

        // unrelated nav is unaffected
        expect(screen.getByRole('link', { name: 'Dashboard' })).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Secrets' })).toBeInTheDocument();
    });

    it('shows the Access Control group for an admin user', () => {
        mockUseAuth.mockReturnValue({ isAdmin: true } as unknown as ReturnType<typeof useAuth>);
        renderSidebar();

        expect(screen.getByRole('button', { name: 'Access Control' })).toBeInTheDocument();
        expect(screen.getByRole('link', { name: 'Users' })).toBeInTheDocument();
    });

    it('applies the active style to the top-level leaf matching the current route', () => {
        window.history.pushState({}, '', '/dashboard');
        renderSidebar();

        const dashboardLink = screen.getByRole('link', { name: 'Dashboard' });
        expect(dashboardLink).toHaveClass('font-medium');
        expect(dashboardLink).toHaveStyle({ backgroundColor: 'var(--accent-subtle)' });

        const projectsLink = screen.getByRole('link', { name: 'Projects' });
        expect(projectsLink).toHaveClass('font-normal');
        expect(projectsLink).not.toHaveStyle({ backgroundColor: 'var(--accent-subtle)' });
    });

    it('treats a nested sub-route as active for the matching leaf (prefix match)', () => {
        window.history.pushState({}, '', '/projects/42');
        renderSidebar();

        expect(screen.getByRole('link', { name: 'Projects' })).toHaveClass('font-medium');
        expect(screen.getByRole('link', { name: 'Dashboard' })).toHaveClass('font-normal');
    });

    it(
        'auto-expands a group whose child route is active even when sidebarExpanded has it collapsed, ' +
            'so a user landing directly on a nested route (deep link, refresh) sees both the bolded ' +
            'group header and the active child leaf itself',
        () => {
            window.history.pushState({}, '', '/integrations/connect');
            renderSidebar();

            const integrationsButton = screen.getByRole('button', { name: 'Integrations' });
            expect(integrationsButton).toHaveStyle({ color: 'var(--text-primary)' });
            expect(screen.getByRole('link', { name: 'Keyorix Connect' })).toBeInTheDocument();
            expect(screen.getByRole('link', { name: 'Keyorix Connect' })).toHaveClass('font-medium');
        }
    );

    it('reveals the active child leaf, styled active, once its group is expanded', () => {
        window.history.pushState({}, '', '/integrations/connect');
        uiState.sidebarExpanded = { ...uiState.sidebarExpanded, integrations: true };
        renderSidebar();

        const link = screen.getByRole('link', { name: 'Keyorix Connect' });
        expect(link).toHaveClass('font-medium');
    });

    it('renders real Links with the expected hrefs and calls onClose when a leaf is clicked', () => {
        const onClose = vi.fn();
        renderSidebar({ onClose });

        const dashboardLink = screen.getByRole('link', { name: 'Dashboard' });
        expect(dashboardLink).toHaveAttribute('href', '/dashboard');

        fireEvent.click(dashboardLink);
        expect(onClose).toHaveBeenCalledTimes(1);
    });

    it('gives the Secrets group children the expected hrefs', () => {
        renderSidebar();

        expect(screen.getByRole('link', { name: 'All Secrets' })).toHaveAttribute('href', '/secrets');
        expect(screen.getByRole('link', { name: 'Secret Expiry' })).toHaveAttribute('href', '/secrets/expiry');
        expect(screen.getByRole('link', { name: 'Rotation Policies' })).toHaveAttribute('href', '/secrets/rotation');
    });

    it('renders a "soon" leaf as a disabled-style link that neither navigates nor closes the sidebar', () => {
        // Tested against a synthetic Leaf item rather than a real NAV entry —
        // every NAV leaf has shipped at this point, and coupling this test to
        // "whatever happens to still be soon today" broke it twice already as
        // placeholders were built out.
        const onClose = vi.fn();
        render(
            <Leaf
                item={{ kind: 'leaf', name: 'Test Feature', href: '/test-feature', soon: true }}
                isActive={() => false}
                onClose={onClose}
            />
        );

        const soonLink = screen.getByRole('link', { name: /Test Feature/ });
        expect(soonLink).toHaveClass('cursor-default');
        expect(within(soonLink).getByText('Soon')).toBeInTheDocument();

        fireEvent.click(soonLink);
        expect(onClose).not.toHaveBeenCalled();
        // preventDefault on click means no navigation occurs despite the <a> tag.
        expect(window.location.pathname).toBe('/');
    });

    it('does not apply a hover background to a "soon" leaf, since it is disabled', () => {
        render(
            <Leaf
                item={{ kind: 'leaf', name: 'Test Feature', href: '/test-feature', soon: true }}
                isActive={() => false}
                onClose={vi.fn()}
            />
        );

        const soonLink = screen.getByRole('link', { name: /Test Feature/ });
        fireEvent.mouseEnter(soonLink);
        expect(soonLink).not.toHaveStyle({ backgroundColor: 'var(--bg-subtle)' });
    });

    it('applies and clears a hover background on a non-active leaf, but not on the active one', () => {
        window.history.pushState({}, '', '/dashboard');
        renderSidebar();

        const projectsLink = screen.getByRole('link', { name: 'Projects' }); // inactive
        fireEvent.mouseEnter(projectsLink);
        expect(projectsLink).toHaveStyle({ backgroundColor: 'var(--bg-subtle)' });
        fireEvent.mouseLeave(projectsLink);
        expect(projectsLink).toHaveStyle({ backgroundColor: '' });

        const dashboardLink = screen.getByRole('link', { name: 'Dashboard' }); // active
        fireEvent.mouseEnter(dashboardLink);
        expect(dashboardLink).not.toHaveStyle({ backgroundColor: 'var(--bg-subtle)' });
        fireEvent.mouseLeave(dashboardLink);
        expect(dashboardLink).toHaveStyle({ backgroundColor: 'var(--accent-subtle)' });
    });

    it('applies and clears a hover background on a group header button', () => {
        renderSidebar();

        const secretsButton = screen.getByRole('button', { name: 'Secrets' });
        fireEvent.mouseEnter(secretsButton);
        expect(secretsButton).toHaveStyle({ backgroundColor: 'var(--bg-subtle)' });
        fireEvent.mouseLeave(secretsButton);
        expect(secretsButton).toHaveStyle({ backgroundColor: '' });
    });

    it('treats a group with no entry at all in sidebarExpanded as collapsed by default (unless active)', () => {
        uiState.sidebarExpanded = {};
        renderSidebar();

        // Secrets isn't active on '/', and has no key in sidebarExpanded at all
        // (as opposed to an explicit `false`) — the `?? false` fallback should
        // still collapse it rather than throw or default open.
        expect(screen.queryByRole('link', { name: 'All Secrets' })).not.toBeInTheDocument();
    });

    it('renders SDKs & CLI as a real, clickable link now that it has shipped', () => {
        uiState.sidebarExpanded = { ...uiState.sidebarExpanded, integrations: true };
        renderSidebar();

        const link = screen.getByRole('link', { name: 'SDKs & CLI' });
        expect(link).toHaveAttribute('href', '/integrations/sdks');
        expect(within(link).queryByText('Soon')).not.toBeInTheDocument();
    });

    it.each([
        ['System Health', '/settings/health'],
        ['Authentication', '/settings/auth'],
        ['Encryption & Keys', '/settings/encryption'],
    ])('shows %s for an admin and hides it for a non-admin', (label, href) => {
        uiState.sidebarExpanded = { ...uiState.sidebarExpanded, settings: true };
        mockUseAuth.mockReturnValue({ isAdmin: true } as unknown as ReturnType<typeof useAuth>);
        const { rerender } = renderSidebar();

        expect(screen.getByRole('link', { name: label })).toHaveAttribute('href', href);

        mockUseAuth.mockReturnValue({ isAdmin: false } as unknown as ReturnType<typeof useAuth>);
        rerender(<Sidebar isOpen={true} onClose={vi.fn()} />);

        expect(screen.queryByRole('link', { name: label })).not.toBeInTheDocument();
        // unaffected sibling leaf in the same, non-admin-gated group
        expect(screen.getByRole('link', { name: 'Appearance' })).toBeInTheDocument();
    });

    it('toggles a collapsed group open on click, calling toggleSidebarGroup and revealing its children', () => {
        const { onClose, rerender } = renderSidebar();

        expect(screen.queryByRole('link', { name: 'Keyorix Connect' })).not.toBeInTheDocument();

        const integrationsButton = screen.getByRole('button', { name: 'Integrations' });
        const chevron = integrationsButton.querySelector('svg.transition-transform');
        expect(chevron).not.toHaveClass('rotate-180');

        fireEvent.click(integrationsButton);

        expect(toggleSidebarGroupMock).toHaveBeenCalledWith('integrations');
        expect(uiState.sidebarExpanded.integrations).toBe(true);

        rerender(<Sidebar isOpen={false} onClose={onClose} />);

        expect(integrationsButton.querySelector('svg.transition-transform')).toHaveClass('rotate-180');
        expect(screen.getByRole('link', { name: 'Keyorix Connect' })).toBeInTheDocument();
    });

    it('toggles an expanded group closed on a second click, hiding its children again', () => {
        uiState.sidebarExpanded = { ...uiState.sidebarExpanded, secrets: true };
        const { onClose, rerender } = renderSidebar();

        expect(screen.getByRole('link', { name: 'All Secrets' })).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Secrets' }));
        expect(toggleSidebarGroupMock).toHaveBeenCalledWith('secrets');
        expect(uiState.sidebarExpanded.secrets).toBe(false);

        rerender(<Sidebar isOpen={false} onClose={onClose} />);

        expect(screen.queryByRole('link', { name: 'All Secrets' })).not.toBeInTheDocument();
    });

    it('applies the className prop to the desktop nav wrapper', () => {
        const { container } = renderSidebar({ className: 'custom-wrapper' });
        expect(container.querySelector('.custom-wrapper')).toBeInTheDocument();
    });

    it('passes onClose through to the stubbed ProjectSwitcher as onNavigate', () => {
        const onClose = vi.fn();
        renderSidebar({ onClose });

        fireEvent.click(screen.getByTestId('project-switcher-stub'));
        expect(onClose).toHaveBeenCalledTimes(1);
    });

    it('renders the mobile dialog nav tree when open and its close button calls onClose', () => {
        const onClose = vi.fn();
        renderSidebar({ isOpen: true, onClose });

        // The always-mounted desktop rail is still in the DOM, but Radix marks
        // it aria-hidden while the modal dialog is open, so only the dialog's
        // own copy of the nav is reachable via role queries.
        const dialog = screen.getByRole('dialog', { name: 'Navigation menu' });
        expect(within(dialog).getByRole('link', { name: 'Dashboard' })).toBeInTheDocument();
        expect(screen.getAllByRole('link', { name: 'Dashboard' })).toHaveLength(1);

        const closeButton = document.querySelector('button.ml-1');
        expect(closeButton).toBeTruthy();

        fireEvent.click(closeButton as HTMLButtonElement);
        expect(onClose).toHaveBeenCalledTimes(1);
    });

    it('does not render the mobile dialog content when closed', () => {
        renderSidebar({ isOpen: false });

        expect(screen.getAllByRole('link', { name: 'Dashboard' })).toHaveLength(1);
        expect(document.querySelector('button.ml-1')).not.toBeInTheDocument();
    });
});
