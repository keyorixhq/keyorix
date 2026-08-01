import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '../../../test/test-utils';
import { Layout } from '../Layout';

// Layout composes Header/Sidebar/Footer/Breadcrumb/ImpersonationBanner/CmdKSearch.
// Sibling agents are covering those components' own internals in parallel, so
// they're stubbed here as trivial components — these tests only exercise
// Layout's own composition and the sidebar-open/cmdk-open state it owns.
vi.mock('../Header', () => ({
    Header: ({ onMenuClick }: { onMenuClick: () => void }) => (
        <button type="button" onClick={onMenuClick}>
            open-sidebar-trigger
        </button>
    ),
}));

vi.mock('../Sidebar', () => ({
    Sidebar: ({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) => (
        <div data-testid="sidebar-stub" data-open={isOpen}>
            <button type="button" onClick={onClose}>
                close-sidebar-trigger
            </button>
        </div>
    ),
}));

vi.mock('../Footer', () => ({
    Footer: () => <div data-testid="footer-stub">footer stub</div>,
}));

vi.mock('../Breadcrumb', () => ({
    Breadcrumb: ({ items }: { items: { name: string }[] }) => (
        <nav data-testid="breadcrumb-stub">{items.map((item) => item.name).join(' / ')}</nav>
    ),
}));

vi.mock('../ImpersonationBanner', () => ({
    ImpersonationBanner: () => <div data-testid="impersonation-banner-stub">impersonation banner stub</div>,
}));

vi.mock('../../ui/CmdKSearch', () => ({
    CmdKSearch: ({ onClose }: { onClose: () => void }) => (
        <div data-testid="cmdk-search-stub">
            cmdk stub
            <button type="button" onClick={onClose}>
                close-cmdk-trigger
            </button>
        </div>
    ),
}));

describe('Layout', () => {
    it('renders the header, sidebar, footer, impersonation banner, and routed content', () => {
        render(
            <Layout>
                <div data-testid="page-content">page content</div>
            </Layout>
        );

        expect(screen.getByText('open-sidebar-trigger')).toBeInTheDocument();
        expect(screen.getByTestId('sidebar-stub')).toBeInTheDocument();
        expect(screen.getByTestId('footer-stub')).toBeInTheDocument();
        expect(screen.getByTestId('impersonation-banner-stub')).toBeInTheDocument();
        expect(screen.getByTestId('page-content')).toBeInTheDocument();
    });

    it('does not render a breadcrumb when no breadcrumbs prop is passed', () => {
        render(
            <Layout>
                <div>content</div>
            </Layout>
        );

        expect(screen.queryByTestId('breadcrumb-stub')).not.toBeInTheDocument();
    });

    it('does not render a breadcrumb when breadcrumbs is an empty array', () => {
        render(
            <Layout breadcrumbs={[]}>
                <div>content</div>
            </Layout>
        );

        expect(screen.queryByTestId('breadcrumb-stub')).not.toBeInTheDocument();
    });

    it('renders the breadcrumb with the given items when breadcrumbs is non-empty', () => {
        render(
            <Layout
                breadcrumbs={[
                    { name: 'Projects', href: '/projects' },
                    { name: 'Detail', current: true },
                ]}
            >
                <div>content</div>
            </Layout>
        );

        expect(screen.getByTestId('breadcrumb-stub')).toHaveTextContent('Projects / Detail');
    });

    it('renders the footer by default (showFooter defaults to true)', () => {
        render(
            <Layout>
                <div>content</div>
            </Layout>
        );

        expect(screen.getByTestId('footer-stub')).toBeInTheDocument();
    });

    it('hides the footer when showFooter is false', () => {
        render(
            <Layout showFooter={false}>
                <div>content</div>
            </Layout>
        );

        expect(screen.queryByTestId('footer-stub')).not.toBeInTheDocument();
    });

    it('applies the className prop to the page-content wrapper', () => {
        render(
            <Layout className="custom-page-class">
                <div data-testid="page-content">content</div>
            </Layout>
        );

        const wrapper = screen.getByTestId('page-content').parentElement;
        expect(wrapper).toHaveClass('flex-1', 'custom-page-class');
    });

    it('starts with the sidebar closed', () => {
        render(
            <Layout>
                <div>content</div>
            </Layout>
        );

        expect(screen.getByTestId('sidebar-stub')).toHaveAttribute('data-open', 'false');
    });

    it('opens the sidebar when the header menu trigger is clicked', () => {
        render(
            <Layout>
                <div>content</div>
            </Layout>
        );

        fireEvent.click(screen.getByText('open-sidebar-trigger'));

        expect(screen.getByTestId('sidebar-stub')).toHaveAttribute('data-open', 'true');
    });

    it('closes the sidebar when the sidebar close trigger is invoked', () => {
        render(
            <Layout>
                <div>content</div>
            </Layout>
        );

        fireEvent.click(screen.getByText('open-sidebar-trigger'));
        expect(screen.getByTestId('sidebar-stub')).toHaveAttribute('data-open', 'true');

        fireEvent.click(screen.getByText('close-sidebar-trigger'));
        expect(screen.getByTestId('sidebar-stub')).toHaveAttribute('data-open', 'false');
    });

    it('does not render the Cmd-K search overlay by default', () => {
        render(
            <Layout>
                <div>content</div>
            </Layout>
        );

        expect(screen.queryByTestId('cmdk-search-stub')).not.toBeInTheDocument();
    });

    it('opens the Cmd-K search overlay on Ctrl+K', () => {
        render(
            <Layout>
                <div>content</div>
            </Layout>
        );

        fireEvent.keyDown(window, { key: 'k', ctrlKey: true });

        expect(screen.getByTestId('cmdk-search-stub')).toBeInTheDocument();
    });

    it('opens the Cmd-K search overlay on Cmd+K (metaKey)', () => {
        render(
            <Layout>
                <div>content</div>
            </Layout>
        );

        fireEvent.keyDown(window, { key: 'k', metaKey: true });

        expect(screen.getByTestId('cmdk-search-stub')).toBeInTheDocument();
    });

    it('toggles the Cmd-K search overlay closed on a second Ctrl+K', () => {
        render(
            <Layout>
                <div>content</div>
            </Layout>
        );

        fireEvent.keyDown(window, { key: 'k', ctrlKey: true });
        expect(screen.getByTestId('cmdk-search-stub')).toBeInTheDocument();

        fireEvent.keyDown(window, { key: 'k', ctrlKey: true });
        expect(screen.queryByTestId('cmdk-search-stub')).not.toBeInTheDocument();
    });

    it('closes the Cmd-K search overlay when its onClose is invoked', () => {
        render(
            <Layout>
                <div>content</div>
            </Layout>
        );

        fireEvent.keyDown(window, { key: 'k', ctrlKey: true });
        expect(screen.getByTestId('cmdk-search-stub')).toBeInTheDocument();

        fireEvent.click(screen.getByText('close-cmdk-trigger'));

        expect(screen.queryByTestId('cmdk-search-stub')).not.toBeInTheDocument();
    });

    it('ignores keydown events for keys other than k', () => {
        render(
            <Layout>
                <div>content</div>
            </Layout>
        );

        fireEvent.keyDown(window, { key: 'j', ctrlKey: true });

        expect(screen.queryByTestId('cmdk-search-stub')).not.toBeInTheDocument();
    });

    it('removes the keydown listener on unmount', () => {
        const removeEventListenerSpy = vi.spyOn(window, 'removeEventListener');

        const { unmount } = render(
            <Layout>
                <div>content</div>
            </Layout>
        );
        unmount();

        expect(removeEventListenerSpy).toHaveBeenCalledWith('keydown', expect.any(Function));
        removeEventListenerSpy.mockRestore();
    });
});
