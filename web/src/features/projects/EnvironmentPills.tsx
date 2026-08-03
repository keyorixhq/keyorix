import React from 'react';
import { clsx } from 'clsx';
import type { ProjectEnvironment } from '../../services/projects';

interface EnvironmentPillsProps {
    environments: ProjectEnvironment[];
    activeEnvName: string;
    onChange: (envName: string) => void;
    isLoading?: boolean;
}

/**
 * Horizontal selectable environment chips.
 * Active = filled accent background. Inactive = outline.
 * Used inside the Secrets tab of ProjectDetailPage.
 */
export const EnvironmentPills: React.FC<EnvironmentPillsProps> = ({
    environments,
    activeEnvName,
    onChange,
    isLoading,
}) => {
    if (isLoading) {
        return (
            <div className="flex gap-2 mb-5">
                {[1, 2, 3].map((i) => (
                    <div
                        key={i}
                        className="h-7 w-24 rounded-full animate-pulse"
                        style={{ backgroundColor: 'var(--bg-muted)' }}
                    />
                ))}
            </div>
        );
    }

    if (environments.length === 0) return null;

    return (
        <div className="flex flex-wrap gap-2 mb-5">
            {environments.map((env) => {
                const active = env.name === activeEnvName;
                return (
                    <button
                        key={env.id}
                        type="button"
                        onClick={() => onChange(env.name)}
                        className={clsx(
                            'px-3 py-1 rounded-full text-xs font-medium transition-colors duration-100 border'
                        )}
                        style={
                            active
                                ? {
                                      backgroundColor: 'var(--accent)',
                                      borderColor: 'var(--accent)',
                                      color: '#fff',
                                  }
                                : {
                                      backgroundColor: 'transparent',
                                      borderColor: 'var(--border-strong)',
                                      color: 'var(--text-secondary)',
                                  }
                        }
                    >
                        {env.name.charAt(0).toUpperCase() + env.name.slice(1)}
                    </button>
                );
            })}
        </div>
    );
};
