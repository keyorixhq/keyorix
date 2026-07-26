import React from 'react';
import { SunIcon, MoonIcon, ComputerDesktopIcon } from '@heroicons/react/24/outline';
import { useUIStore, Theme } from '../../store/uiStore';

interface ThemeOption {
    value: Theme;
    label: string;
    description: string;
    icon: React.ComponentType<React.SVGProps<SVGSVGElement>>;
}

const THEME_OPTIONS: ThemeOption[] = [
    {
        value: 'light',
        label: 'Light',
        description: 'White background — good for bright environments and print.',
        icon: SunIcon,
    },
    {
        value: 'dark',
        label: 'Dark',
        description: 'Default. Easier on the eyes in low-light conditions.',
        icon: MoonIcon,
    },
    {
        value: 'system',
        label: 'System',
        description: 'Follows your OS appearance setting automatically.',
        icon: ComputerDesktopIcon,
    },
];

export const AppearancePage: React.FC = () => {
    const { theme, setTheme } = useUIStore();

    return (
        <div className="max-w-2xl mx-auto px-6 py-8">
            <div className="mb-8">
                <h1 className="text-2xl font-bold tracking-tight" style={{ color: 'var(--text-primary)' }}>
                    Appearance
                </h1>
                <p className="mt-1 text-sm" style={{ color: 'var(--text-muted)' }}>
                    Choose how Keyorix looks to you. This setting is stored locally in your browser.
                </p>
            </div>

            <div
                className="rounded-xl border overflow-hidden"
                style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}
            >
                <div className="px-6 py-4 border-b" style={{ borderColor: 'var(--border)' }}>
                    <h2
                        className="text-sm font-semibold uppercase tracking-widest"
                        style={{ color: 'var(--text-muted)' }}
                    >
                        Theme
                    </h2>
                </div>

                <div className="divide-y" style={{ borderColor: 'var(--border)' }}>
                    {THEME_OPTIONS.map((opt) => {
                        const selected = theme === opt.value;
                        const Icon = opt.icon;
                        return (
                            <label
                                key={opt.value}
                                className="flex items-center gap-4 px-6 py-4 cursor-pointer transition-colors"
                                style={{ backgroundColor: selected ? 'var(--accent-subtle)' : undefined }}
                                onMouseEnter={(e) => {
                                    if (!selected)
                                        (e.currentTarget as HTMLElement).style.backgroundColor = 'var(--bg-subtle)';
                                }}
                                onMouseLeave={(e) => {
                                    if (!selected) (e.currentTarget as HTMLElement).style.backgroundColor = '';
                                }}
                            >
                                <input
                                    type="radio"
                                    name="theme"
                                    value={opt.value}
                                    checked={selected}
                                    onChange={() => setTheme(opt.value)}
                                    className="sr-only"
                                />
                                {/* Custom radio indicator */}
                                <div
                                    className="shrink-0 h-4 w-4 rounded-full border-2 flex items-center justify-center transition-colors"
                                    style={{
                                        borderColor: selected ? 'var(--accent)' : 'var(--border-strong)',
                                    }}
                                >
                                    {selected && (
                                        <div
                                            className="h-2 w-2 rounded-full"
                                            style={{ backgroundColor: 'var(--accent)' }}
                                        />
                                    )}
                                </div>

                                <Icon
                                    className="h-5 w-5 shrink-0"
                                    style={{ color: selected ? 'var(--accent)' : 'var(--text-muted)' }}
                                />

                                <div className="flex-1 min-w-0">
                                    <p className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>
                                        {opt.label}
                                    </p>
                                    <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
                                        {opt.description}
                                    </p>
                                </div>
                            </label>
                        );
                    })}
                </div>
            </div>
        </div>
    );
};
