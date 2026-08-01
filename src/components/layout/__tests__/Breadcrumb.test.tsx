import { describe, it, expect } from 'vitest';
import { render, screen, within } from '../../../test/test-utils';
import { Breadcrumb, BreadcrumbItem } from '../Breadcrumb';

describe('Breadcrumb', () => {
    it('always renders a Home link to /dashboard, even with an empty items array', () => {
        render(<Breadcrumb items={[]} />);
        const homeLink = screen.getByRole('link', { name: 'Home' });
        expect(homeLink).toHaveAttribute('href', '/dashboard');
        // No item <li>s beyond the Home one.
        expect(screen.getAllByRole('listitem')).toHaveLength(1);
    });

    it('renders each crumb label in order with a separator before each one', () => {
        const items: BreadcrumbItem[] = [
            { name: 'Projects', href: '/projects' },
            { name: 'my-project', href: '/projects/my-project' },
            { name: 'Settings', current: true },
        ];
        render(<Breadcrumb items={items} />);

        const listItems = screen.getAllByRole('listitem');
        // Home + 3 crumbs.
        expect(listItems).toHaveLength(4);

        // Labels appear in document order.
        const nav = screen.getByRole('navigation', { name: 'Breadcrumb' });
        const text = nav.textContent ?? '';
        expect(text.indexOf('Projects')).toBeLessThan(text.indexOf('my-project'));
        expect(text.indexOf('my-project')).toBeLessThan(text.indexOf('Settings'));

        // A separator chevron renders ahead of every crumb (including Home's own item
        // does not have one, so exactly `items.length` chevrons are present).
        const chevrons = nav.querySelectorAll('svg[aria-hidden="true"]');
        // 1 home icon + 3 chevron separators.
        expect(chevrons).toHaveLength(4);
    });

    it('renders a crumb with an href (and not current) as a real Link with the href attribute', () => {
        const items: BreadcrumbItem[] = [{ name: 'Projects', href: '/projects' }];
        render(<Breadcrumb items={items} />);

        const link = screen.getByRole('link', { name: 'Projects' });
        expect(link).toHaveAttribute('href', '/projects');
        expect(link.tagName).toBe('A');
    });

    it('renders a crumb without an href as plain text, not a link', () => {
        const items: BreadcrumbItem[] = [{ name: 'Untitled Project' }];
        render(<Breadcrumb items={items} />);

        expect(screen.queryByRole('link', { name: 'Untitled Project' })).not.toBeInTheDocument();
        const text = screen.getByText('Untitled Project');
        expect(text.tagName).toBe('SPAN');
    });

    it('renders the current crumb as plain text with aria-current="page", even if it has an href', () => {
        const items: BreadcrumbItem[] = [{ name: 'Settings', href: '/settings', current: true }];
        render(<Breadcrumb items={items} />);

        expect(screen.queryByRole('link', { name: 'Settings' })).not.toBeInTheDocument();
        const current = screen.getByText('Settings');
        expect(current.tagName).toBe('SPAN');
        expect(current).toHaveAttribute('aria-current', 'page');
    });

    it('does not set aria-current on a non-current crumb', () => {
        const items: BreadcrumbItem[] = [{ name: 'Projects', href: '/projects' }];
        render(<Breadcrumb items={items} />);

        const link = screen.getByRole('link', { name: 'Projects' });
        expect(link).not.toHaveAttribute('aria-current');
    });

    it('applies the current text styling to a current crumb without an href', () => {
        // Bug note: item.current is only reflected in aria-current and text color when the
        // crumb also renders as a <span> (i.e. it lacks an href, or has one but is current).
        // The Link branch's `aria-current={item.current ? 'page' : undefined}` is dead code:
        // that branch only executes when `!item.current`, so it can never actually be 'page'.
        // Not a user-visible bug (harmless dead expression), so left undocumented-but-noted here
        // rather than modified, per scope discipline.
        const items: BreadcrumbItem[] = [{ name: 'Final Step', current: true }];
        render(<Breadcrumb items={items} />);

        const current = screen.getByText('Final Step');
        expect(current).toHaveClass('text-gray-900');
        expect(current).not.toHaveClass('text-gray-500');
    });

    it('applies the non-current muted styling to a plain-text crumb without current set', () => {
        const items: BreadcrumbItem[] = [{ name: 'No Link No Current' }];
        render(<Breadcrumb items={items} />);

        const span = screen.getByText('No Link No Current');
        expect(span).toHaveClass('text-gray-500');
        expect(span).not.toHaveClass('text-gray-900');
    });

    it('renders duplicate crumb names without throwing (uses item.name as the React key)', () => {
        const items: BreadcrumbItem[] = [{ name: 'Duplicate' }, { name: 'Duplicate', current: true }];
        expect(() => render(<Breadcrumb items={items} />)).not.toThrow();
        expect(screen.getAllByText('Duplicate')).toHaveLength(2);
    });

    it('applies a custom className to the nav element alongside the base classes', () => {
        render(<Breadcrumb items={[]} className="custom-class" />);
        const nav = screen.getByRole('navigation', { name: 'Breadcrumb' });
        expect(nav).toHaveClass('flex');
        expect(nav).toHaveClass('custom-class');
    });

    it('scopes each crumb to its own list item', () => {
        const items: BreadcrumbItem[] = [
            { name: 'Projects', href: '/projects' },
            { name: 'Settings', current: true },
        ];
        render(<Breadcrumb items={items} />);

        const listItems = screen.getAllByRole('listitem');
        // listItems[0] is the Home entry; crumbs follow in order.
        expect(within(listItems[1]).getByText('Projects')).toBeInTheDocument();
        expect(within(listItems[2]).getByText('Settings')).toBeInTheDocument();
    });
});
