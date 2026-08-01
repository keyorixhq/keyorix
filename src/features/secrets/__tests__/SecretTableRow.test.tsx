import { describe, it, expect, vi } from 'vitest';
import { render, screen, within, fireEvent } from '../../../test/test-utils';
import { SecretTableRow } from '../SecretTableRow';
import { Secret } from '../../../types';

// Mirrors the component's own formatDate() so the assertion is correct
// regardless of the timezone the test runs in.
const formatDate = (d: string) =>
    new Intl.DateTimeFormat('en', { year: 'numeric', month: 'short', day: 'numeric' }).format(new Date(d));

const baseSecret: Secret = {
    id: 42,
    name: 'db-password',
    type: 'password',
    environment: 'production',
    isShared: false,
    shareCount: 0,
    lastModified: '2026-01-15T10:00:00Z',
    owner: 'alice',
    permissions: [],
    metadata: {},
    tags: [],
};

// Helper: SecretTableRow renders a <tr>, so it must be wrapped in a real
// <table><tbody> to avoid React DOM-nesting warnings and to make row-scoped
// queries (getByRole('row')) work as they would in the real app.
const renderRow = (props: Partial<React.ComponentProps<typeof SecretTableRow>> = {}) => {
    const defaultProps: React.ComponentProps<typeof SecretTableRow> = {
        secret: baseSecret,
        isSelected: false,
        onToggleSelect: vi.fn(),
        onView: vi.fn(),
        onEdit: vi.fn(),
        onDelete: vi.fn(),
        onShare: vi.fn(),
        onRotate: vi.fn(),
        onCopy: vi.fn(),
        copyingId: null,
        copiedId: null,
        copyErrorId: null,
    };
    const merged = { ...defaultProps, ...props };
    return {
        ...render(
            <table>
                <tbody>
                    <SecretTableRow {...merged} />
                </tbody>
            </table>
        ),
        props: merged,
    };
};

describe('SecretTableRow', () => {
    it('renders name, type badge, environment, and modified date/owner cell', () => {
        renderRow();
        const row = screen.getByRole('row');
        expect(within(row).getByText('db-password')).toBeInTheDocument();
        expect(within(row).getByText('password')).toBeInTheDocument();
        expect(within(row).getByText('production')).toBeInTheDocument();
        expect(within(row).getByText(formatDate(baseSecret.lastModified))).toBeInTheDocument();
        expect(within(row).getByText('by alice')).toBeInTheDocument();
    });

    it('defaults the environment cell to "production" when environment is empty', () => {
        renderRow({ secret: { ...baseSecret, environment: '' } });
        const row = screen.getByRole('row');
        expect(within(row).getByText('production')).toBeInTheDocument();
    });

    it('renders up to 3 tags plus a "+N more" overflow indicator', () => {
        renderRow({ secret: { ...baseSecret, tags: ['a', 'b', 'c', 'd', 'e'] } });
        const row = screen.getByRole('row');
        expect(within(row).getByText('a')).toBeInTheDocument();
        expect(within(row).getByText('b')).toBeInTheDocument();
        expect(within(row).getByText('c')).toBeInTheDocument();
        expect(within(row).queryByText('d')).not.toBeInTheDocument();
        expect(within(row).getByText('+2 more')).toBeInTheDocument();
    });

    it('renders no tag chips when there are no tags', () => {
        renderRow({ secret: { ...baseSecret, tags: [] } });
        const row = screen.getByRole('row');
        expect(within(row).queryByText(/more$/)).not.toBeInTheDocument();
    });

    it('shows a classification badge, defaulting to Unclassified when unset', () => {
        renderRow();
        expect(screen.getByText('Unclassified')).toBeInTheDocument();
    });

    it('shows the correct classification label when set', () => {
        renderRow({ secret: { ...baseSecret, classification: 'confidential' } });
        expect(screen.getByText('Confidential')).toBeInTheDocument();
    });

    it('shows "Private" when the secret is not shared', () => {
        renderRow({ secret: { ...baseSecret, isShared: false } });
        expect(screen.getByText('Private')).toBeInTheDocument();
    });

    it('shows the share count when the secret is shared', () => {
        renderRow({ secret: { ...baseSecret, isShared: true, shareCount: 3 } });
        expect(screen.getByText('3 shares')).toBeInTheDocument();
        expect(screen.queryByText('Private')).not.toBeInTheDocument();
    });

    it('reflects isSelected on the checkbox and applies the selected row background', () => {
        renderRow({ isSelected: true });
        const row = screen.getByRole('row');
        const checkbox = within(row).getByRole('checkbox');
        expect(checkbox).toBeChecked();
        expect(row.className).toContain('bg-accent-subtle');
    });

    it('renders an unchecked checkbox when not selected', () => {
        renderRow({ isSelected: false });
        const checkbox = screen.getByRole('checkbox');
        expect(checkbox).not.toBeChecked();
    });

    it('calls onToggleSelect with the secret id when the checkbox is toggled', () => {
        const onToggleSelect = vi.fn();
        renderRow({ onToggleSelect });
        fireEvent.click(screen.getByRole('checkbox'));
        expect(onToggleSelect).toHaveBeenCalledWith(42);
    });

    it('calls onView with the secret when the View button is clicked', () => {
        const onView = vi.fn();
        renderRow({ onView });
        fireEvent.click(screen.getByTitle('View'));
        expect(onView).toHaveBeenCalledWith(baseSecret);
    });

    it('calls onEdit with the secret when the Edit button is clicked', () => {
        const onEdit = vi.fn();
        renderRow({ onEdit });
        fireEvent.click(screen.getByTitle('Edit'));
        expect(onEdit).toHaveBeenCalledWith(baseSecret);
    });

    it('calls onRotate with the secret when the Rotate button is clicked', () => {
        const onRotate = vi.fn();
        renderRow({ onRotate });
        fireEvent.click(screen.getByTitle('Rotate'));
        expect(onRotate).toHaveBeenCalledWith(baseSecret);
    });

    it('calls onShare with the secret when the Share button is clicked', () => {
        const onShare = vi.fn();
        renderRow({ onShare });
        fireEvent.click(screen.getByTitle('Share'));
        expect(onShare).toHaveBeenCalledWith(baseSecret);
    });

    it('calls onDelete with the secret when the Delete button is clicked', () => {
        const onDelete = vi.fn();
        renderRow({ onDelete });
        fireEvent.click(screen.getByTitle('Delete'));
        expect(onDelete).toHaveBeenCalledWith(baseSecret);
    });

    it('does not render the automated-rotation button when onAutoRotate is not provided', () => {
        renderRow();
        expect(screen.queryByTitle('Automated rotation')).not.toBeInTheDocument();
    });

    it('renders and wires the automated-rotation button when onAutoRotate is provided', () => {
        const onAutoRotate = vi.fn();
        renderRow({ onAutoRotate });
        const button = screen.getByTitle('Automated rotation');
        fireEvent.click(button);
        expect(onAutoRotate).toHaveBeenCalledWith(baseSecret);
    });

    describe('copy button states', () => {
        it('idle: shows the duplicate icon, is enabled, and is not red', () => {
            renderRow({ copyingId: null, copiedId: null, copyErrorId: null });
            const button = screen.getByTitle('Copy value');
            expect(button).not.toBeDisabled();
            expect(button.className).not.toContain('text-red-500');
            expect(button.querySelector('svg')).toBeInTheDocument();
        });

        it('in-flight: disables the button and swaps in a spinner when copyingId matches', () => {
            renderRow({ copyingId: 42 });
            const button = screen.getByTitle('Copy value');
            expect(button).toBeDisabled();
            expect(button.querySelector('.animate-spin')).toBeInTheDocument();
        });

        it('success: shows a green check icon when copiedId matches', () => {
            renderRow({ copiedId: 42 });
            const button = screen.getByTitle('Copy value');
            expect(button).not.toBeDisabled();
            const icon = button.querySelector('svg');
            expect(icon).toBeInTheDocument();
            expect(icon?.getAttribute('class')).toContain('text-green-500');
        });

        it('error: applies the red text class when copyErrorId matches', () => {
            renderRow({ copyErrorId: 42 });
            const button = screen.getByTitle('Copy value');
            expect(button.className).toContain('text-red-500');
            expect(button).not.toBeDisabled();
        });

        it("does not treat another row's in-flight/copied/error id as this row's state", () => {
            renderRow({ copyingId: 99, copiedId: 100, copyErrorId: 101 });
            const button = screen.getByTitle('Copy value');
            expect(button).not.toBeDisabled();
            expect(button.className).not.toContain('text-red-500');
            expect(button.querySelector('.animate-spin')).not.toBeInTheDocument();
        });

        it('calls onCopy with the secret when the copy button is clicked', () => {
            const onCopy = vi.fn();
            renderRow({ onCopy });
            fireEvent.click(screen.getByTitle('Copy value'));
            expect(onCopy).toHaveBeenCalledWith(baseSecret);
        });

        it('does not fire onCopy while the copy button is disabled (in-flight)', () => {
            const onCopy = vi.fn();
            renderRow({ onCopy, copyingId: 42 });
            fireEvent.click(screen.getByTitle('Copy value'));
            expect(onCopy).not.toHaveBeenCalled();
        });
    });

    it.each([
        ['password', 'password'],
        ['api_key', 'api_key'],
        ['text', 'text'],
        ['certificate', 'cert'],
        ['json', 'json'],
    ] as const)('renders the %s type badge with label "%s"', (type, label) => {
        renderRow({ secret: { ...baseSecret, type } });
        expect(screen.getByText(label)).toBeInTheDocument();
    });
});
