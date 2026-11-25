import React from 'react';
import { SunIcon, MoonIcon, ComputerDesktopIcon } from '@heroicons/react/24/outline';
import { useUIStore, type Theme } from '../../store/uiStore';

// Three visible positions, in the order a person reads them: light, follow the
// operating system, dark. Every position is on screen at once and the current
// one is highlighted, so the control says what it does without a tooltip.
const OPTIONS: { value: Theme; label: string; Icon: React.ComponentType<React.SVGProps<SVGSVGElement>> }[] = [
    { value: 'light', label: 'Light', Icon: SunIcon },
    { value: 'system', label: 'Match system', Icon: ComputerDesktopIcon },
    { value: 'dark', label: 'Dark', Icon: MoonIcon },
];

export const ThemeSwitch: React.FC = () => {
    const { theme, setTheme } = useUIStore();
    const refs = React.useRef<Array<HTMLButtonElement | null>>([]);

    // ARIA radio group: one tab stop (the selected option), arrow keys move
    // the selection, as a native radio group would.
    const onKeyDown = (event: React.KeyboardEvent, index: number) => {
        let next = -1;
        if (event.key === 'ArrowRight' || event.key === 'ArrowDown') next = (index + 1) % OPTIONS.length;
        else if (event.key === 'ArrowLeft' || event.key === 'ArrowUp')
            next = (index - 1 + OPTIONS.length) % OPTIONS.length;
        const option = OPTIONS[next];
        if (!option) return;
        event.preventDefault();
        setTheme(option.value);
        refs.current[next]?.focus();
    };

    return (
        <div
            role="radiogroup"
            aria-label="Theme"
            data-testid="theme-switch"
            className="inline-flex items-center rounded-full border p-0.5"
            style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}
        >
            {OPTIONS.map(({ value, label, Icon }, index) => {
                const selected = theme === value;
                return (
                    <button
                        key={value}
                        ref={(el) => {
                            refs.current[index] = el;
                        }}
                        type="button"
                        role="radio"
                        aria-checked={selected}
                        aria-label={label}
                        title={label}
                        tabIndex={selected ? 0 : -1}
                        data-testid={`theme-switch-${value}`}
                        onClick={() => setTheme(value)}
                        onKeyDown={(event) => onKeyDown(event, index)}
                        className="rounded-full p-2 transition-colors focus:outline-hidden focus-visible:ring-2 focus-visible:ring-blue-500"
                        style={{
                            backgroundColor: selected ? 'var(--bg-muted)' : 'transparent',
                            color: selected ? 'var(--text-primary)' : 'var(--text-muted)',
                        }}
                    >
                        <Icon className="h-5 w-5" aria-hidden="true" />
                    </button>
                );
            })}
        </div>
    );
};
