import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { AppearancePage } from '../AppearancePage';
import { useUIStore } from '../../../store/uiStore';

// AppearancePage reads/writes theme via the real, referentially-stable uiStore
// actions (see CLAUDE.md), so we exercise the actual Zustand store rather than
// mocking it, resetting it to a known baseline before each test.
describe('AppearancePage', () => {
    beforeEach(() => {
        useUIStore.setState({
            sidebarOpen: true,
            activeModal: null,
            modalData: null,
            theme: 'dark',
            sidebarExpanded: { secrets: true, access: true, integrations: false, settings: false },
        });
    });

    it('renders the page heading and description', () => {
        render(<AppearancePage />);

        expect(screen.getByRole('heading', { name: 'Appearance', level: 1 })).toBeInTheDocument();
        expect(
            screen.getByText('Choose how Keyorix looks to you. This setting is stored locally in your browser.')
        ).toBeInTheDocument();
    });

    it('renders all three theme options with labels and descriptions', () => {
        render(<AppearancePage />);

        expect(screen.getByText('Light')).toBeInTheDocument();
        expect(screen.getByText('White background — good for bright environments and print.')).toBeInTheDocument();

        expect(screen.getByText('Dark')).toBeInTheDocument();
        expect(screen.getByText('Default. Easier on the eyes in low-light conditions.')).toBeInTheDocument();

        expect(screen.getByText('System')).toBeInTheDocument();
        expect(screen.getByText('Follows your OS appearance setting automatically.')).toBeInTheDocument();

        expect(screen.getAllByRole('radio')).toHaveLength(3);
    });

    it('marks the currently-active theme radio as checked', () => {
        useUIStore.setState({ theme: 'dark' });
        render(<AppearancePage />);

        // Accessible names are anchored to the start ("^") because each <label>'s
        // text includes both its title and its description, and Dark's description
        // ("...low-light conditions.") would otherwise falsely match /light/i.
        expect(screen.getByRole('radio', { name: /^dark/i })).toBeChecked();
        expect(screen.getByRole('radio', { name: /^light/i })).not.toBeChecked();
        expect(screen.getByRole('radio', { name: /^system/i })).not.toBeChecked();
    });

    it('reflects a non-default active theme (light) as checked', () => {
        useUIStore.setState({ theme: 'light' });
        render(<AppearancePage />);

        expect(screen.getByRole('radio', { name: /^light/i })).toBeChecked();
        expect(screen.getByRole('radio', { name: /^dark/i })).not.toBeChecked();
        expect(screen.getByRole('radio', { name: /^system/i })).not.toBeChecked();
    });

    it('reflects the system theme as checked', () => {
        useUIStore.setState({ theme: 'system' });
        render(<AppearancePage />);

        expect(screen.getByRole('radio', { name: /^system/i })).toBeChecked();
        expect(screen.getByRole('radio', { name: /^dark/i })).not.toBeChecked();
        expect(screen.getByRole('radio', { name: /^light/i })).not.toBeChecked();
    });

    it('clicking the Light option calls the real store setTheme action and updates state', async () => {
        const user = userEvent.setup();
        render(<AppearancePage />);

        expect(useUIStore.getState().theme).toBe('dark');

        await user.click(screen.getByRole('radio', { name: /^light/i }));

        expect(useUIStore.getState().theme).toBe('light');
        expect(screen.getByRole('radio', { name: /^light/i })).toBeChecked();
        expect(screen.getByRole('radio', { name: /^dark/i })).not.toBeChecked();
    });

    it('clicking the System option calls setTheme and updates state', async () => {
        const user = userEvent.setup();
        render(<AppearancePage />);

        await user.click(screen.getByRole('radio', { name: /^system/i }));

        expect(useUIStore.getState().theme).toBe('system');
        expect(screen.getByRole('radio', { name: /^system/i })).toBeChecked();
    });

    it('clicking the already-selected theme keeps it selected (idempotent)', async () => {
        const user = userEvent.setup();
        render(<AppearancePage />);

        expect(useUIStore.getState().theme).toBe('dark');
        await user.click(screen.getByRole('radio', { name: /^dark/i }));

        expect(useUIStore.getState().theme).toBe('dark');
        expect(screen.getByRole('radio', { name: /^dark/i })).toBeChecked();
    });

    it('applies the data-theme attribute to the document element when a theme is selected', async () => {
        const user = userEvent.setup();
        render(<AppearancePage />);

        await user.click(screen.getByRole('radio', { name: /^light/i }));

        expect(document.documentElement.getAttribute('data-theme')).toBe('light');
    });

    it("resets an unselected option's hover background on mouse leave, but leaves the selected option's style alone", () => {
        render(<AppearancePage />);
        const lightLabel = screen.getByRole('radio', { name: /^light/i }).closest('label') as HTMLElement;
        const darkLabel = screen.getByRole('radio', { name: /^dark/i }).closest('label') as HTMLElement; // selected by default

        fireEvent.mouseEnter(lightLabel);
        expect(lightLabel.style.backgroundColor).toBe('var(--bg-subtle)');
        fireEvent.mouseLeave(lightLabel);
        expect(lightLabel.style.backgroundColor).toBe('');

        // The selected option's hover handlers early-return, so its React-controlled
        // inline background is never touched by mouseenter/mouseleave.
        const before = darkLabel.style.backgroundColor;
        fireEvent.mouseEnter(darkLabel);
        fireEvent.mouseLeave(darkLabel);
        expect(darkLabel.style.backgroundColor).toBe(before);
    });
});
