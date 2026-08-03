import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { FolderIcon } from '@heroicons/react/24/outline';
import { Dropdown, DropdownButton, type DropdownItem } from '../Dropdown';

function openMenu(trigger: HTMLElement) {
    // jsdom's Radix DropdownMenu.Trigger only opens on a real pointerdown (a
    // click alone does not flip data-state to "open").
    fireEvent.pointerDown(trigger, { pointerId: 1, pointerType: 'mouse', button: 0 });
    fireEvent.click(trigger);
}

function selectItem(item: HTMLElement) {
    fireEvent.pointerDown(item, { pointerId: 1, pointerType: 'mouse', button: 0 });
    fireEvent.pointerUp(item, { pointerId: 1, pointerType: 'mouse', button: 0 });
    fireEvent.click(item);
}

describe('Dropdown', () => {
    it('opens the menu and shows item labels', () => {
        const items: DropdownItem[] = [{ label: 'Edit', value: 'edit' }];
        render(<Dropdown trigger={<button>Open</button>} items={items} />);
        openMenu(screen.getByText('Open'));
        expect(screen.getByText('Edit')).toBeInTheDocument();
    });

    it('opens aligned to the start when align is "left"', () => {
        const items: DropdownItem[] = [{ label: 'Edit', value: 'edit' }];
        render(<Dropdown trigger={<button>Open</button>} items={items} align="left" />);
        openMenu(screen.getByText('Open'));
        expect(screen.getByText('Edit')).toBeInTheDocument();
    });

    it('renders an empty menu when items is nullish', () => {
        render(<Dropdown trigger={<button>Open</button>} items={undefined as unknown as DropdownItem[]} />);
        openMenu(screen.getByText('Open'));
        expect(screen.queryByRole('menuitem')).not.toBeInTheDocument();
    });

    it('calls the item onClick handler when selected', () => {
        const onClick = vi.fn();
        const items: DropdownItem[] = [{ label: 'Delete', value: 'delete', onClick }];
        render(<Dropdown trigger={<button>Open</button>} items={items} />);
        openMenu(screen.getByText('Open'));
        selectItem(screen.getByText('Delete'));
        expect(onClick).toHaveBeenCalledOnce();
    });

    it('marks a disabled item as disabled', () => {
        const items: DropdownItem[] = [{ label: 'Delete', value: 'delete', disabled: true }];
        render(<Dropdown trigger={<button>Open</button>} items={items} />);
        openMenu(screen.getByText('Open'));
        expect(screen.getByRole('menuitem', { name: 'Delete' })).toHaveAttribute('data-disabled');
    });

    it('renders a danger item with its icon', () => {
        const items: DropdownItem[] = [{ label: 'Remove', value: 'remove', danger: true, icon: FolderIcon }];
        render(<Dropdown trigger={<button>Open</button>} items={items} />);
        openMenu(screen.getByText('Open'));
        const item = screen.getByRole('menuitem', { name: /Remove/ });
        expect(item.querySelector('svg')).toBeInTheDocument();
    });

    it('applies a custom className to the trigger wrapper', () => {
        render(<Dropdown trigger={<span>T</span>} items={[]} className="custom-trigger" />);
        expect(screen.getByText('T').parentElement).toHaveClass('custom-trigger');
    });
});

describe('DropdownButton', () => {
    it('renders its children and a chevron icon', () => {
        render(<DropdownButton items={[{ label: 'A', value: 'a' }]}>Actions</DropdownButton>);
        const button = screen.getByRole('button', { name: /Actions/ });
        expect(button).toBeInTheDocument();
        expect(button.querySelector('svg')).toBeInTheDocument();
    });

    it('applies the primary variant and lg size classes', () => {
        render(
            <DropdownButton items={[{ label: 'A', value: 'a' }]} variant="primary" size="lg">
                Actions
            </DropdownButton>
        );
        const button = screen.getByRole('button', { name: /Actions/ });
        expect(button.className).toContain('bg-[var(--accent)]');
        expect(button.className).toContain('text-base');
    });

    it('applies the ghost variant and sm size classes', () => {
        render(
            <DropdownButton items={[{ label: 'A', value: 'a' }]} variant="ghost" size="sm" align="left">
                Actions
            </DropdownButton>
        );
        const button = screen.getByRole('button', { name: /Actions/ });
        expect(button.className).toContain('hover:bg-subtle');
    });

    it('can be disabled', () => {
        render(
            <DropdownButton items={[{ label: 'A', value: 'a' }]} disabled>
                Actions
            </DropdownButton>
        );
        expect(screen.getByRole('button', { name: /Actions/ })).toBeDisabled();
    });

    it('opens the menu and shows items when clicked', () => {
        render(<DropdownButton items={[{ label: 'Delete', value: 'delete' }]}>Actions</DropdownButton>);
        openMenu(screen.getByRole('button', { name: /Actions/ }));
        expect(screen.getByText('Delete')).toBeInTheDocument();
    });
});
