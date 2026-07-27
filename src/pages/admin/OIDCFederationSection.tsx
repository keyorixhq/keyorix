import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { PlusIcon, TrashIcon } from '@heroicons/react/24/outline';
import { apiClient } from '../../services/client';
import { Alert } from '../../components/ui/Alert';
import { Loading } from '../../components/ui/Loading';
import { Button } from '../../components/ui/Button';
import { Modal } from '../../components/ui/Modal';
import type { ServiceAccount } from '../../types/serviceAccounts';

interface OIDCTrustConfig {
    id: number;
    name: string;
    description: string;
    issuer_url: string;
    audience: string;
    subject_pattern: string;
    service_account_id: number;
    service_account_name: string;
    created_at: string;
    created_by: string;
}

interface OIDCTrustConfigCreate {
    name: string;
    description: string;
    issuer_url: string;
    audience: string;
    subject_pattern: string;
    service_account_id: number;
}

const ISSUER_PRESETS = [
    {
        key: 'github',
        label: 'GitHub Actions',
        issuer_url: 'https://token.actions.githubusercontent.com',
        audience: 'keyorix',
        subject_hint: 'repo:owner/repo:ref:refs/heads/main',
    },
    {
        key: 'gitlab',
        label: 'GitLab CI',
        issuer_url: 'https://gitlab.com',
        audience: 'keyorix',
        subject_hint: 'project_path:group/project:ref_type:branch:ref:main',
    },
    {
        key: 'gcp',
        label: 'GCP',
        issuer_url: 'https://accounts.google.com',
        audience: 'keyorix',
        subject_hint: '',
    },
    {
        key: 'azure',
        label: 'Azure / Entra',
        issuer_url: 'https://sts.windows.net/{tenant-id}/',
        audience: 'keyorix',
        subject_hint: '',
    },
    {
        key: 'custom',
        label: 'Custom',
        issuer_url: '',
        audience: 'keyorix',
        subject_hint: '',
    },
] as const;

type PresetKey = (typeof ISSUER_PRESETS)[number]['key'];

const INPUT_STYLE: React.CSSProperties = {
    backgroundColor: 'var(--bg-app)',
    color: 'var(--text-primary)',
    borderColor: 'var(--border-strong)',
};

function formatDate(iso: string): string {
    if (!iso) return '—';
    try {
        return new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
    } catch {
        return iso;
    }
}

function useOIDCTrustConfigs() {
    return useQuery({
        queryKey: ['oidc-trust-configs'],
        queryFn: async () => {
            const res = await apiClient.get<{ data: OIDCTrustConfig[] }>('/api/v1/oidc/trust');
            return res.data.data ?? [];
        },
        retry: false,
    });
}

function useAddOIDCTrust() {
    const qc = useQueryClient();
    return useMutation({
        mutationFn: async (payload: OIDCTrustConfigCreate) => {
            const res = await apiClient.post<{ data: OIDCTrustConfig }>('/api/v1/oidc/trust', payload);
            return res.data.data;
        },
        onSuccess: () => qc.invalidateQueries({ queryKey: ['oidc-trust-configs'] }),
    });
}

function useDeleteOIDCTrust() {
    const qc = useQueryClient();
    return useMutation({
        mutationFn: async (id: number) => {
            await apiClient.delete(`/api/v1/oidc/trust/${id}`);
        },
        onSuccess: () => qc.invalidateQueries({ queryKey: ['oidc-trust-configs'] }),
    });
}

interface Props {
    serviceAccounts: ServiceAccount[];
}

export const OIDCFederationSection: React.FC<Props> = ({ serviceAccounts }) => {
    const { data: trustConfigs = [], isLoading, error } = useOIDCTrustConfigs();
    const addMutation = useAddOIDCTrust();
    const deleteMutation = useDeleteOIDCTrust();

    const [showAdd, setShowAdd] = useState(false);
    const [confirmDeleteId, setConfirmDeleteId] = useState<number | null>(null);
    const [addError, setAddError] = useState('');

    const [formName, setFormName] = useState('');
    const [formDescription, setFormDescription] = useState('');
    const [formPreset, setFormPreset] = useState<PresetKey>('github');
    const [formIssuerUrl, setFormIssuerUrl] = useState<string>(ISSUER_PRESETS[0].issuer_url);
    const [formAudience, setFormAudience] = useState<string>(ISSUER_PRESETS[0].audience);
    const [formSubjectPattern, setFormSubjectPattern] = useState<string>(ISSUER_PRESETS[0].subject_hint);
    const [formSaId, setFormSaId] = useState<number | ''>('');

    const httpStatus = (error as any)?.response?.status as number | undefined;
    const backendNotReady = httpStatus === 404 || httpStatus === 501;

    function openAdd() {
        setFormName('');
        setFormDescription('');
        const preset = ISSUER_PRESETS[0];
        setFormPreset(preset.key);
        setFormIssuerUrl(preset.issuer_url);
        setFormAudience(preset.audience);
        setFormSubjectPattern(preset.subject_hint);
        setFormSaId('');
        setAddError('');
        setShowAdd(true);
    }

    function selectPreset(key: PresetKey) {
        setFormPreset(key);
        const preset = ISSUER_PRESETS.find((p) => p.key === key)!;
        setFormIssuerUrl(preset.issuer_url);
        setFormAudience(preset.audience);
        setFormSubjectPattern(preset.subject_hint ?? '');
    }

    async function submitAdd() {
        if (!formName.trim()) { setAddError('Name is required.'); return; }
        if (!formIssuerUrl.trim()) { setAddError('Issuer URL is required.'); return; }
        if (!formSubjectPattern.trim()) { setAddError('Subject pattern is required.'); return; }
        if (!formSaId) { setAddError('Select a service account to bind.'); return; }
        setAddError('');
        try {
            await addMutation.mutateAsync({
                name: formName.trim(),
                description: formDescription.trim(),
                issuer_url: formIssuerUrl.trim(),
                audience: formAudience.trim(),
                subject_pattern: formSubjectPattern.trim(),
                service_account_id: formSaId as number,
            });
            setShowAdd(false);
        } catch (e: any) {
            setAddError(e?.response?.data?.message ?? 'Failed to create trust configuration.');
        }
    }

    async function doDelete(id: number) {
        try {
            await deleteMutation.mutateAsync(id);
            setConfirmDeleteId(null);
        } catch {
            // keep confirmation open so the user sees it failed
        }
    }

    return (
        <div>
            <div className="flex items-center justify-between mb-6">
                <div>
                    <h2 className="text-lg font-semibold text-base-primary">OIDC Workload Identity Federation</h2>
                    <p className="text-sm text-base-muted mt-0.5">
                        Let CI/CD systems exchange short-lived OIDC tokens for Keyorix access — no static secrets needed.
                    </p>
                </div>
                <Button variant="default" onClick={openAdd} disabled={!!backendNotReady}>
                    <PlusIcon className="h-4 w-4 mr-1.5" />
                    Add Trust Config
                </Button>
            </div>

            {backendNotReady && (
                <Alert
                    type="info"
                    title="OIDC federation not yet available in this deployment"
                    message="The /api/v1/oidc/trust endpoint is not implemented in the current backend. Trust configurations will be manageable here once the backend ships this feature."
                    className="mb-6"
                />
            )}

            {error && !backendNotReady && (
                <Alert
                    type="error"
                    title="Failed to load trust configurations"
                    message={(error as any)?.response?.data?.message ?? 'Check server connectivity and try again.'}
                    className="mb-6"
                />
            )}

            {isLoading && <Loading className="py-16" />}

            {!isLoading && !error && trustConfigs.length === 0 && (
                <div className="text-center py-14 text-base-muted">
                    <p className="text-sm">No trust configurations yet. Add one to enable keyless CI/CD access.</p>
                </div>
            )}

            {!isLoading && trustConfigs.length > 0 && (
                <div className="space-y-3 mb-8">
                    {trustConfigs.map((cfg) => (
                        <div
                            key={cfg.id}
                            className="bg-surface border border-base rounded-lg p-4 flex items-start justify-between gap-4"
                        >
                            <div className="min-w-0 flex-1">
                                <p className="text-sm font-medium text-base-primary">{cfg.name}</p>
                                {cfg.description && (
                                    <p className="text-xs text-base-muted mt-0.5">{cfg.description}</p>
                                )}
                                <div className="mt-2 flex flex-wrap gap-x-6 gap-y-1 text-xs text-base-muted">
                                    <span>
                                        <span className="font-medium">Issuer:</span> {cfg.issuer_url}
                                    </span>
                                    <span>
                                        <span className="font-medium">Subject:</span> {cfg.subject_pattern}
                                    </span>
                                    <span>
                                        <span className="font-medium">Bound SA:</span> {cfg.service_account_name}
                                    </span>
                                    <span>
                                        <span className="font-medium">Added:</span> {formatDate(cfg.created_at)}
                                    </span>
                                </div>
                            </div>
                            <div className="flex items-center gap-2 flex-shrink-0 pt-0.5">
                                {confirmDeleteId === cfg.id ? (
                                    <>
                                        <span className="text-xs text-base-muted">Delete?</span>
                                        <button
                                            type="button"
                                            className="text-xs text-red-500 hover:text-red-600 font-medium"
                                            onClick={() => doDelete(cfg.id)}
                                            disabled={deleteMutation.isPending}
                                        >
                                            Confirm
                                        </button>
                                        <button
                                            type="button"
                                            className="text-xs text-base-muted hover:text-base-primary"
                                            onClick={() => setConfirmDeleteId(null)}
                                        >
                                            Cancel
                                        </button>
                                    </>
                                ) : (
                                    <button
                                        type="button"
                                        className="p-1.5 text-base-muted hover:text-red-600 hover:bg-red-50 rounded-sm transition-colors"
                                        onClick={() => setConfirmDeleteId(cfg.id)}
                                        title="Delete trust config"
                                    >
                                        <TrashIcon className="h-4 w-4" />
                                    </button>
                                )}
                            </div>
                        </div>
                    ))}
                </div>
            )}

            <HowToUseGuide />

            {/* ── Add trust config modal ─────────────────────────────────────── */}
            <Modal isOpen={showAdd} onClose={() => setShowAdd(false)} title="Add trust configuration" size="lg">
                <div className="space-y-4">
                    {addError && <Alert type="error" message={addError} />}

                    <div>
                        <label htmlFor="oidc-name-input" className="block text-sm font-medium text-base-secondary mb-1">
                            Name <span className="text-red-500">*</span>
                        </label>
                        <input
                            id="oidc-name-input"
                            type="text"
                            value={formName}
                            onChange={(e) => setFormName(e.target.value)}
                            placeholder="e.g. github-deploy"
                            className="w-full px-3 py-2 text-sm border border-base rounded-lg focus:outline-hidden focus:ring-2 focus:ring-blue-500"
                            style={INPUT_STYLE}
                        />
                    </div>

                    <div>
                        <label htmlFor="oidc-description-input" className="block text-sm font-medium text-base-secondary mb-1">Description</label>
                        <input
                            id="oidc-description-input"
                            type="text"
                            value={formDescription}
                            onChange={(e) => setFormDescription(e.target.value)}
                            placeholder="Optional"
                            className="w-full px-3 py-2 text-sm border border-base rounded-lg focus:outline-hidden focus:ring-2 focus:ring-blue-500"
                            style={INPUT_STYLE}
                        />
                    </div>

                    <div>
                        <label htmlFor="oidc-issuer-preset" className="block text-sm font-medium text-base-secondary mb-2">Issuer preset</label>
                        <div className="flex flex-wrap gap-2">
                            {ISSUER_PRESETS.map((p, i) => (
                                <button
                                    key={p.key}
                                    id={i === 0 ? 'oidc-issuer-preset' : undefined}
                                    type="button"
                                    onClick={() => selectPreset(p.key)}
                                    className={`px-3 py-1.5 text-xs rounded-md border transition-colors ${
                                        formPreset === p.key
                                            ? 'border-blue-500 bg-blue-50 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300'
                                            : 'border-base text-base-muted hover:border-blue-400'
                                    }`}
                                >
                                    {p.label}
                                </button>
                            ))}
                        </div>
                    </div>

                    <div>
                        <label htmlFor="oidc-issuer-url-input" className="block text-sm font-medium text-base-secondary mb-1">
                            Issuer URL <span className="text-red-500">*</span>
                        </label>
                        <input
                            id="oidc-issuer-url-input"
                            type="url"
                            value={formIssuerUrl}
                            onChange={(e) => setFormIssuerUrl(e.target.value)}
                            placeholder="https://token.actions.githubusercontent.com"
                            className="w-full px-3 py-2 text-sm border border-base rounded-lg focus:outline-hidden focus:ring-2 focus:ring-blue-500 font-mono"
                            style={INPUT_STYLE}
                        />
                    </div>

                    <div className="grid grid-cols-2 gap-3">
                        <div>
                            <label htmlFor="oidc-audience-input" className="block text-sm font-medium text-base-secondary mb-1">Audience</label>
                            <input
                                id="oidc-audience-input"
                                type="text"
                                value={formAudience}
                                onChange={(e) => setFormAudience(e.target.value)}
                                placeholder="keyorix"
                                className="w-full px-3 py-2 text-sm border border-base rounded-lg focus:outline-hidden focus:ring-2 focus:ring-blue-500 font-mono"
                                style={INPUT_STYLE}
                            />
                        </div>
                        <div>
                            <label htmlFor="oidc-subject-pattern-input" className="block text-sm font-medium text-base-secondary mb-1">
                                Subject pattern <span className="text-red-500">*</span>
                            </label>
                            <input
                                id="oidc-subject-pattern-input"
                                type="text"
                                value={formSubjectPattern}
                                onChange={(e) => setFormSubjectPattern(e.target.value)}
                                placeholder="repo:owner/repo:*"
                                className="w-full px-3 py-2 text-sm border border-base rounded-lg focus:outline-hidden focus:ring-2 focus:ring-blue-500 font-mono"
                                style={INPUT_STYLE}
                            />
                            <p className="text-xs text-base-muted mt-1">Supports <code>*</code> wildcards</p>
                        </div>
                    </div>

                    <div>
                        <label htmlFor="oidc-service-account-select" className="block text-sm font-medium text-base-secondary mb-1">
                            Bind to service account <span className="text-red-500">*</span>
                        </label>
                        <select
                            id="oidc-service-account-select"
                            value={formSaId}
                            onChange={(e) => setFormSaId(e.target.value ? Number(e.target.value) : '')}
                            className="w-full px-3 py-2 text-sm border border-base rounded-lg focus:outline-hidden focus:ring-2 focus:ring-blue-500"
                            style={INPUT_STYLE}
                        >
                            <option value="">Select a service account…</option>
                            {serviceAccounts
                                .filter((sa) => sa.is_active)
                                .map((sa) => (
                                    <option key={sa.id} value={sa.id}>
                                        {sa.name}
                                    </option>
                                ))}
                        </select>
                        <p className="text-xs text-base-muted mt-1">
                            Only the permissions assigned to this SA will be granted to the exchanged token.
                        </p>
                    </div>

                    <div className="flex justify-end gap-3 pt-2">
                        <Button variant="ghost" onClick={() => setShowAdd(false)} disabled={addMutation.isPending}>
                            Cancel
                        </Button>
                        <Button variant="default" onClick={submitAdd} disabled={addMutation.isPending}>
                            {addMutation.isPending ? 'Adding…' : 'Add Trust Configuration'}
                        </Button>
                    </div>
                </div>
            </Modal>
        </div>
    );
};

function HowToUseGuide() {
    const [open, setOpen] = useState(false);

    return (
        <div className="border border-base rounded-lg overflow-hidden">
            <button
                type="button"
                onClick={() => setOpen((v) => !v)}
                className="w-full flex items-center justify-between px-4 py-3 text-sm font-medium text-base-secondary hover:bg-subtle transition-colors text-left"
            >
                <span>How to use OIDC federation in GitHub Actions</span>
                <span className="text-base-muted text-xs">{open ? '▲' : '▼'}</span>
            </button>
            {open && (
                <div className="px-4 pb-4 pt-2 space-y-3">
                    <p className="text-xs text-base-muted">
                        Add this step to your workflow. The runner requests a short-lived OIDC token from GitHub and
                        exchanges it for a Keyorix access token — no secrets stored in GitHub.
                    </p>
                    <pre
                        className="text-xs rounded-md p-3 overflow-x-auto leading-relaxed"
                        style={{
                            backgroundColor: 'var(--bg-subtle)',
                            color: 'var(--text-secondary)',
                            border: '1px solid var(--border)',
                        }}
                    >{`permissions:
  id-token: write   # required for OIDC

steps:
  - name: Exchange OIDC token for Keyorix token
    id: kx-auth
    run: |
      OIDC_TOKEN=$(curl -sSfL \\
        "\${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=keyorix" \\
        -H "Authorization: bearer \${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \\
        | jq -r '.value')

      KX_TOKEN=$(curl -sSf https://api.keyorix.io/api/v1/oidc/token \\
        -d "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer" \\
        -d "assertion=\${OIDC_TOKEN}" \\
        -d "trust_config_id=\${KX_TRUST_CONFIG_ID}" \\
        | jq -r '.access_token')

      echo "::add-mask::\${KX_TOKEN}"
      echo "token=\${KX_TOKEN}" >> "$GITHUB_OUTPUT"

  - name: Use Keyorix secrets
    env:
      KX_TOKEN: \${{ steps.kx-auth.outputs.token }}
    run: |
      curl -sSf https://api.keyorix.io/api/v1/secrets \\
        -H "Authorization: Bearer \${KX_TOKEN}"`}
                    </pre>
                    <p className="text-xs text-base-muted">
                        Set <code>KX_TRUST_CONFIG_ID</code> as a repository variable (not a secret) — it is not sensitive.
                    </p>
                </div>
            )}
        </div>
    );
}
