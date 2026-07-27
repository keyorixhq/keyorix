import React, { useEffect, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import {
    EyeIcon,
    EyeSlashIcon,
    DocumentDuplicateIcon,
    PencilIcon,
    ShareIcon,
    TrashIcon,
    ClockIcon,
    TagIcon,
    MapPinIcon,
    UserIcon,
    KeyIcon,
    ArrowPathIcon,
    ShieldExclamationIcon,
    ShieldCheckIcon,
} from '@heroicons/react/24/outline';
import {
    useSecretVersions,
    useRotateSecret,
    useSecretRisk,
    useClassifySecret,
    useRollbackSecret,
    useSecretAccessors,
    useSecretAccessLog,
    useSecretAuditTrail,
    useSecretTags,
    useSetSecretTags,
    useSecretDescription,
    useSetSecretDescription,
    useCopySecret,
    useSuspendSecret,
    useResumeSecret,
} from './api';
import { TransferOwnership } from './TransferOwnership';
import { SecretDependenciesSection } from './SecretDependenciesSection';
import { CertificatePanel } from './CertificatePanel';
import { CLASSIFICATION_LEVELS, classificationMeta } from './classification';
import { RiskBand, Secret } from '../../types';
import { copyToClipboard } from '../../utils';
import { queryKeys } from '../../lib/queryClient';
import { Button } from '../../components/ui/Button';
import { Spinner, Loading } from '../../components/ui/Loading';
import { Alert } from '../../components/ui/Alert';
import { Modal } from '../../components/ui/Modal';
import { Textarea } from '../../components/ui/Textarea';

const formatDate = (d: string | Date) =>
    new Intl.DateTimeFormat('en', { year: 'numeric', month: 'short', day: 'numeric' }).format(new Date(d));
const formatTime = (d: string | Date) =>
    new Intl.DateTimeFormat('en', { hour: '2-digit', minute: '2-digit' }).format(new Date(d));

const relativeFromNow = (d: string | Date): string => {
    const days = Math.floor((Date.now() - new Date(d).getTime()) / 86_400_000);
    if (days <= 0) return 'today';
    if (days === 1) return 'yesterday';
    if (days < 30) return `${days} days ago`;
    const months = Math.floor(days / 30);
    if (months < 12) return `${months} month${months === 1 ? '' : 's'} ago`;
    const years = Math.floor(days / 365);
    return `${years} year${years === 1 ? '' : 's'} ago`;
};

// Human-readable label for an audit event_type; falls back to the raw type with the
// "secret." prefix stripped so unknown/new events still render sensibly.
const auditEventLabel = (eventType: string): string => {
    const KNOWN: Record<string, string> = {
        'secret.created': 'Created',
        'secret.updated': 'Updated',
        'secret.rotated': 'Rotated',
        'secret.rolled_back': 'Rolled back',
        'secret.suspended': 'Suspended',
        'secret.resumed': 'Resumed',
        'secret.shared': 'Shared',
        'secret.unshared': 'Unshared',
        'secret.owner_transferred': 'Owner transferred',
        'secret.classified': 'Reclassified',
        'secret.deleted': 'Deleted',
    };
    return KNOWN[eventType] ?? eventType.replace(/^secret\./, '').replaceAll('_', ' ');
};

const RISK_BAND_STYLE: Record<RiskBand, { label: string; color: string }> = {
    low: { label: 'Low risk', color: '#10b981' },
    medium: { label: 'Medium risk', color: '#f59e0b' },
    high: { label: 'High risk', color: '#ef4444' },
};

const factorColor = (score: number): string => {
    const mediumOrLow = score >= 34 ? '#f59e0b' : '#10b981';
    return score >= 67 ? '#ef4444' : mediumOrLow;
};

const formatSecretValue = (value: string, type: string): string => {
    if (type === 'json') {
        try {
            return JSON.stringify(JSON.parse(value), null, 2);
        } catch {
            return value;
        }
    }
    return value;
};

const TYPE_COLORS: Record<string, string> = {
    text: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
    password: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200',
    api_key: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
    certificate: 'bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200',
    json: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200',
};

const getTypeColor = (type: string): string => TYPE_COLORS[type] ?? TYPE_COLORS['text']!;

const PERMISSION_COLORS: Record<string, string> = {
    owner: 'bg-purple-100 text-purple-800 dark:bg-purple-900/40 dark:text-purple-300',
    write: 'bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-300',
};
const DEFAULT_PERMISSION_COLOR = 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300';
const getPermissionColor = (permission: string): string =>
    PERMISSION_COLORS[permission] ?? DEFAULT_PERMISSION_COLOR;

interface SecretDetailViewProps {
    secret: Secret;
    onEdit?: (secret: Secret) => void;
    onShare?: (secret: Secret) => void;
    onDelete?: (secret: Secret) => void;
    onClose?: () => void;
}

export const SecretDetailView: React.FC<SecretDetailViewProps> = ({ secret, onEdit, onShare, onDelete, onClose }) => {
    const [showValue, setShowValue] = useState(false);
    const [copySuccess, setCopySuccess] = useState(false);
    const [showRotate, setShowRotate] = useState(false);
    const [rotateValue, setRotateValue] = useState('');

    const [classification, setClassification] = useState<string>(secret.classification ?? '');
    const [status, setStatus] = useState<string>(secret.status ?? 'active');
    const suspendMutation = useSuspendSecret(secret.id);
    const resumeMutation = useResumeSecret(secret.id);
    const copyMutation = useCopySecret(secret.id);
    const [copyMsg, setCopyMsg] = useState('');

    const handleCopy = () => {
        const envInput = window.prompt('Copy to which environment? Enter the target environment ID (same project):');
        const envId = Number(envInput);
        if (!envInput || !Number.isInteger(envId) || envId <= 0) return;
        const name = window.prompt('Name for the copy (leave blank to keep the same name):') || undefined;
        setCopyMsg('');
        copyMutation.mutate(
            { environmentId: envId, ...(name ? { name } : {}) },
            {
                onSuccess: () => setCopyMsg(`Copied to environment ${envId}.`),
                onError: (err: any) =>
                    setCopyMsg(err?.response?.data?.message ?? err?.response?.data?.error ?? 'Copy failed.'),
            }
        );
    };
    const suspended = status === 'suspended';
    const handleToggleSuspend = () => {
        if (suspended) {
            resumeMutation.mutate(undefined, { onSuccess: () => setStatus('active') });
        } else {
            if (!window.confirm('Suspend this secret? Value reads will be blocked until you resume it.')) return;
            suspendMutation.mutate(undefined, { onSuccess: () => setStatus('suspended') });
        }
    };

    const { data: versions, isLoading, error } = useSecretVersions(secret.id, showValue);
    const queryClient = useQueryClient();
    // Revealed plaintext otherwise lingers in the React Query cache for the
    // default gcTime after the value is hidden or the view is closed —
    // evict it explicitly rather than relying on that timeout.
    useEffect(() => {
        if (!showValue) {
            queryClient.removeQueries({ queryKey: queryKeys.secrets.versions(secret.id) });
        }
    }, [showValue, secret.id, queryClient]);
    useEffect(() => {
        return () => {
            queryClient.removeQueries({ queryKey: queryKeys.secrets.versions(secret.id) });
        };
    }, [secret.id, queryClient]);
    const rotateMutation = useRotateSecret(secret.id);
    const rollbackMutation = useRollbackSecret(secret.id);
    const { data: accessors } = useSecretAccessors(secret.id);
    const { data: accessLog } = useSecretAccessLog(secret.id);
    const { data: auditTrail } = useSecretAuditTrail(secret.id);
    const { data: secretTags = [] } = useSecretTags(secret.id);
    const setTags = useSetSecretTags(secret.id);
    const [tagDraft, setTagDraft] = useState('');
    const { data: description = '' } = useSecretDescription(secret.id);
    const setDescription = useSetSecretDescription(secret.id);
    const [descDraft, setDescDraft] = useState<string | null>(null);
    const { data: risk } = useSecretRisk(secret.id);
    const classifyMutation = useClassifySecret(secret.id);

    const handleRollback = (version: number) => {
        if (!window.confirm(`Roll back to version ${version}? Its value will be re-instated as a new version.`)) return;
        rollbackMutation.mutate(version, { onSuccess: () => setShowValue(false) });
    };

    // Optimistically reflect the new level; revert if the server rejects it.
    const handleClassify = (level: string) => {
        const previous = classification;
        if (level === previous) return;
        setClassification(level);
        classifyMutation.mutate(level, {
            onError: () => setClassification(previous),
        });
    };

    const closeRotate = () => {
        setShowRotate(false);
        setRotateValue('');
        rotateMutation.reset();
    };

    const handleRotate = () => {
        if (!rotateValue.trim()) return;
        rotateMutation.mutate(rotateValue, {
            onSuccess: () => {
                setShowValue(false); // force a re-reveal so the new version is fetched
                closeRotate();
            },
        });
    };

    const latestVersion =
        versions && versions.length > 0
            ? versions.reduce((a, b) => (a.VersionNumber >= b.VersionNumber ? a : b))
            : null;
    const secretValue = latestVersion ? atob(latestVersion.EncryptedValue) : null;

    const handleCopyValue = async (value: string): Promise<void> => {
        try {
            await copyToClipboard(value);
            setCopySuccess(true);
            setTimeout(() => setCopySuccess(false), 2000);
        } catch (error) {
            console.error('Failed to copy to clipboard:', error);
        }
    };

    const handleToggleValue = () => {
        setShowValue(!showValue);
    };

    const revealButtonContent = showValue ? (
        <>
            <EyeSlashIcon className="h-4 w-4 mr-2" />
            Hide
        </>
    ) : (
        <>
            <EyeIcon className="h-4 w-4 mr-2" />
            Reveal
        </>
    );

    const revealedValueContent = secretValue ? (
        <div className="bg-gray-50 dark:bg-gray-700 rounded-md p-4">
            {secret.type === 'json' ? (
                <pre className="text-sm font-mono text-gray-900 dark:text-white whitespace-pre-wrap overflow-x-auto">
                    {formatSecretValue(secretValue, secret.type)}
                </pre>
            ) : (
                <div className="text-sm font-mono text-gray-900 dark:text-white break-all">
                    {secretValue}
                </div>
            )}
        </div>
    ) : null;

    const loadingOrValue = isLoading ? (
        <div className="bg-gray-50 dark:bg-gray-700 rounded-md p-4">
            <Loading />
        </div>
    ) : revealedValueContent;

    const secretValueDisplay = !showValue ? (
        <div className="bg-gray-50 dark:bg-gray-700 rounded-md p-4 text-center">
            <div className="text-gray-400 dark:text-gray-500 mb-2">
                <EyeSlashIcon className="h-8 w-8 mx-auto" />
            </div>
            <p className="text-sm text-gray-500 dark:text-gray-400">
                Secret value is hidden for security. Click "Reveal" to view.
            </p>
        </div>
    ) : loadingOrValue;

    const handleTagKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
        if (e.key !== 'Enter') return;
        const t = tagDraft.trim().toLowerCase();
        if (!t || secretTags.includes(t)) {
            setTagDraft('');
            return;
        }
        setTags.mutate([...secretTags, t], { onSuccess: () => setTagDraft('') });
    };

    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="flex items-start justify-between">
                <div className="flex-1">
                    <div className="flex items-center space-x-3">
                        <h2 className="text-2xl font-semibold text-gray-900 dark:text-white">{secret.name}</h2>
                        <span
                            className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getTypeColor(secret.type)}`}
                        >
                            {secret.type}
                        </span>
                        <span
                            data-testid="classification-badge"
                            className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${classificationMeta(classification).color}`}
                            title="Data classification (ISO 27001 A.5.12)"
                        >
                            <ShieldCheckIcon className="h-3.5 w-3.5 mr-1" />
                            {classificationMeta(classification).label}
                        </span>
                        {suspended && (
                            <span
                                data-testid="suspended-badge"
                                className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300"
                                title="Value reads are blocked while suspended"
                            >
                                Suspended
                            </span>
                        )}
                    </div>

                    <div className="mt-2 flex items-center space-x-4 text-sm text-gray-500 dark:text-gray-400">
                        <div className="flex items-center">
                            <MapPinIcon className="h-4 w-4 mr-1" />
                            {secret.environment || 'No environment'}
                        </div>
                        <div className="flex items-center">
                            <UserIcon className="h-4 w-4 mr-1" />
                            {secret.owner}
                        </div>
                        <div className="flex items-center">
                            <ClockIcon className="h-4 w-4 mr-1" />
                            {formatDate(secret.lastModified)} at {formatTime(secret.lastModified)}
                        </div>
                        <div className="flex items-center">
                            <ArrowPathIcon className="h-4 w-4 mr-1" />
                            {secret.lastRotatedAt
                                ? `Rotated ${relativeFromNow(secret.lastRotatedAt)}`
                                : 'Never rotated'}
                        </div>
                        <label className="flex items-center">
                            <span className="sr-only">Classification</span>
                            <ShieldCheckIcon className="h-4 w-4 mr-1" />
                            <select
                                aria-label="Classification"
                                value={classification}
                                disabled={classifyMutation.isPending}
                                onChange={(e) => handleClassify(e.target.value)}
                                className="bg-transparent text-sm text-gray-500 dark:text-gray-400 border-0 focus:ring-0 cursor-pointer disabled:opacity-50"
                            >
                                {CLASSIFICATION_LEVELS.map((level) => (
                                    <option key={level || 'unclassified'} value={level}>
                                        {classificationMeta(level).label}
                                    </option>
                                ))}
                            </select>
                        </label>
                    </div>
                    <div className="mt-2">
                        <TransferOwnership secretId={secret.id} currentOwner={secret.owner} />
                    </div>
                </div>

                <div className="flex items-center space-x-2">
                    <Button variant="outline" size="sm" onClick={() => onEdit?.(secret)}>
                        <PencilIcon className="h-4 w-4 mr-2" />
                        Edit
                    </Button>
                    <Button variant="outline" size="sm" onClick={() => setShowRotate(true)}>
                        <ArrowPathIcon className="h-4 w-4 mr-2" />
                        Rotate
                    </Button>
                    <Button variant="outline" size="sm" onClick={() => onShare?.(secret)}>
                        <ShareIcon className="h-4 w-4 mr-2" />
                        Share
                    </Button>
                    <Button
                        variant="outline"
                        size="sm"
                        onClick={handleCopy}
                        disabled={copyMutation.isPending}
                        title="Copy this secret into another environment (same project)"
                    >
                        <DocumentDuplicateIcon className="h-4 w-4 mr-2" />
                        Copy
                    </Button>
                    <Button
                        variant="outline"
                        size="sm"
                        onClick={handleToggleSuspend}
                        disabled={suspendMutation.isPending || resumeMutation.isPending}
                        className={suspended ? '' : 'text-amber-600 hover:text-amber-700'}
                    >
                        {suspended ? 'Resume' : 'Suspend'}
                    </Button>
                    <Button
                        variant="outline"
                        size="sm"
                        onClick={() => onDelete?.(secret)}
                        className="text-red-600 hover:text-red-700"
                    >
                        <TrashIcon className="h-4 w-4 mr-2" />
                        Delete
                    </Button>
                </div>
            </div>

            {copyMsg && (
                <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
                    {copyMsg}
                </p>
            )}

            {/* Secret Value */}
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
                <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-medium text-gray-900 dark:text-white flex items-center">
                        <KeyIcon className="h-5 w-5 mr-2" />
                        Secret Value
                    </h3>
                    <div className="flex items-center space-x-2">
                        <Button
                            variant="outline"
                            size="sm"
                            onClick={handleToggleValue}
                            disabled={showValue && isLoading}
                        >
                            {showValue && isLoading ? (
                                <Spinner size="sm" />
                            ) : revealButtonContent}
                        </Button>

                        {showValue && secretValue && (
                            <Button
                                variant="outline"
                                size="sm"
                                onClick={() => handleCopyValue(secretValue)}
                                className={copySuccess ? 'text-green-600' : ''}
                            >
                                <DocumentDuplicateIcon className="h-4 w-4 mr-2" />
                                {copySuccess ? 'Copied!' : 'Copy'}
                            </Button>
                        )}
                    </div>
                </div>

                {!!error && (
                    <Alert
                        type="error"
                        title="Failed to load secret value"
                        message="There was an error loading the secret value. Please try again."
                    />
                )}

                {secretValueDisplay}

                {copySuccess && (
                    <div className="mt-2">
                        <Alert type="success" title="Copied to clipboard" message="Secret value copied to clipboard." />
                    </div>
                )}
            </div>

            {/* Certificate metadata (ADR-054) — for certificate-typed secrets */}
            {secret.type === 'certificate' && <CertificatePanel secretId={secret.id} />}

            {/* Version History */}
            {versions && versions.length > 1 && latestVersion && (
                <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
                    <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">Version History</h3>
                    {rollbackMutation.isError && (
                        <Alert
                            type="error"
                            title="Rollback failed"
                            message={
                                rollbackMutation.error instanceof Error
                                    ? rollbackMutation.error.message
                                    : 'An unexpected error occurred'
                            }
                        />
                    )}
                    <div className="divide-y divide-gray-200 dark:divide-gray-700">
                        {[...versions]
                            .sort((a, b) => b.VersionNumber - a.VersionNumber)
                            .map((v) => (
                                <div key={v.VersionNumber} className="flex items-center justify-between py-2.5">
                                    <div className="flex items-center gap-2 text-sm">
                                        <span className="font-medium text-gray-900 dark:text-white tabular-nums">
                                            v{v.VersionNumber}
                                        </span>
                                        {v.VersionNumber === latestVersion.VersionNumber && (
                                            <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300">
                                                current
                                            </span>
                                        )}
                                        <span className="text-gray-500 dark:text-gray-400">
                                            {new Date(v.CreatedAt).toLocaleString()}
                                        </span>
                                    </div>
                                    {v.VersionNumber !== latestVersion.VersionNumber && (
                                        <Button
                                            variant="outline"
                                            size="sm"
                                            disabled={rollbackMutation.isPending}
                                            onClick={() => handleRollback(v.VersionNumber)}
                                        >
                                            {rollbackMutation.isPending ? 'Rolling back…' : 'Roll back'}
                                        </Button>
                                    )}
                                </div>
                            ))}
                    </div>
                </div>
            )}

            {/* Who can access — effective access list */}
            {accessors && accessors.length > 0 && (
                <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
                    <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-1">Who can access</h3>
                    <p className="text-xs text-gray-500 dark:text-gray-400 mb-4">
                        Users who can read this secret (admins with a role grant are not listed).
                    </p>
                    <div className="divide-y divide-gray-200 dark:divide-gray-700">
                        {accessors.map((a) => (
                            <div key={a.user_id} className="flex items-center justify-between py-2.5 text-sm">
                                <div className="flex items-center gap-2">
                                    <UserIcon className="h-4 w-4 text-gray-400" />
                                    <span className="font-medium text-gray-900 dark:text-white">{a.username}</span>
                                    <span className="text-xs text-gray-500 dark:text-gray-400">{a.source}</span>
                                </div>
                                <span
                                    className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${getPermissionColor(a.permission)}`}
                                >
                                    {a.permission}
                                </span>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* Recent access — who has read this secret */}
            {accessLog && accessLog.length > 0 && (
                <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
                    <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-1">Recent access</h3>
                    <p className="text-xs text-gray-500 dark:text-gray-400 mb-4">
                        Reads of this secret in the last 30 days.
                    </p>
                    <div className="divide-y divide-gray-200 dark:divide-gray-700">
                        {accessLog.slice(0, 25).map((e) => (
                            <div key={`${e.AccessedBy}-${e.AccessTime}-${e.Action}`} className="flex items-center justify-between py-2 text-sm">
                                <div className="flex items-center gap-2 min-w-0">
                                    <UserIcon className="h-4 w-4 text-gray-400 shrink-0" />
                                    <span className="font-medium text-gray-900 dark:text-white">
                                        {e.AccessedBy || 'unknown'}
                                    </span>
                                    <span className="text-xs text-gray-500 dark:text-gray-400 truncate">
                                        {e.Action}
                                        {e.IPAddress ? ` · ${e.IPAddress}` : ''}
                                    </span>
                                </div>
                                <span
                                    className="text-xs text-gray-500 dark:text-gray-400 whitespace-nowrap"
                                    title={new Date(e.AccessTime).toLocaleString()}
                                >
                                    {relativeFromNow(e.AccessTime)}
                                </span>
                            </div>
                        ))}
                    </div>
                    {accessLog.length > 25 && (
                        <p className="text-xs text-gray-400 mt-3">Showing the 25 most recent of {accessLog.length}.</p>
                    )}
                </div>
            )}

            {/* Description — free-text note (editable) */}
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
                <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-1">Description</h3>
                <p className="text-xs text-gray-500 dark:text-gray-400 mb-4">
                    A free-text note — what this secret is for, its upstream, who to contact.
                </p>
                <textarea
                    value={descDraft ?? description}
                    onChange={(e) => setDescDraft(e.target.value)}
                    disabled={setDescription.isPending}
                    rows={3}
                    maxLength={1024}
                    placeholder="No description."
                    className="w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-900 px-3 py-2 text-sm text-gray-900 dark:text-white disabled:opacity-50"
                />
                {descDraft !== null && descDraft !== description && (
                    <div className="mt-2 flex justify-end gap-2">
                        <button
                            type="button"
                            onClick={() => setDescDraft(null)}
                            disabled={setDescription.isPending}
                            className="px-3 py-1 text-sm text-gray-500 hover:text-gray-700 dark:text-gray-400 disabled:opacity-50"
                        >
                            Cancel
                        </button>
                        <button
                            type="button"
                            onClick={() => setDescription.mutate(descDraft, { onSuccess: () => setDescDraft(null) })}
                            disabled={setDescription.isPending}
                            className="px-3 py-1 rounded-md text-sm font-medium text-white disabled:opacity-50"
                            style={{ backgroundColor: 'var(--accent, #2563eb)' }}
                        >
                            {setDescription.isPending ? 'Saving…' : 'Save'}
                        </button>
                    </div>
                )}
            </div>

            {/* Tags — free-form organization labels (editable) */}
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
                <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-1">Tags</h3>
                <p className="text-xs text-gray-500 dark:text-gray-400 mb-4">
                    Free-form labels for organizing and filtering secrets.
                </p>
                <div className="flex flex-wrap items-center gap-2">
                    {secretTags.map((t) => (
                        <span
                            key={t}
                            className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-200"
                        >
                            {t}
                            <button
                                type="button"
                                aria-label={`Remove tag ${t}`}
                                disabled={setTags.isPending}
                                onClick={() => setTags.mutate(secretTags.filter((x) => x !== t))}
                                className="text-gray-400 hover:text-red-500 disabled:opacity-50"
                            >
                                ×
                            </button>
                        </span>
                    ))}
                    {secretTags.length === 0 && <span className="text-xs text-gray-400">No tags yet.</span>}
                </div>
                <input
                    value={tagDraft}
                    onChange={(e) => setTagDraft(e.target.value)}
                    onKeyDown={handleTagKeyDown}
                    disabled={setTags.isPending}
                    placeholder="Add a tag and press Enter…"
                    className="mt-3 w-full rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-900 px-3 py-1.5 text-sm text-gray-900 dark:text-white disabled:opacity-50"
                />
            </div>

            {/* History — what happened to this secret (lifecycle audit trail) */}
            {auditTrail && auditTrail.length > 0 && (
                <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
                    <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-1">History</h3>
                    <p className="text-xs text-gray-500 dark:text-gray-400 mb-4">
                        Lifecycle events for this secret — created, rotated, suspended, shared, and more.
                    </p>
                    <div className="divide-y divide-gray-200 dark:divide-gray-700">
                        {auditTrail.map((e) => (
                            <div key={e.id} className="flex items-center justify-between py-2 text-sm">
                                <div className="flex items-center gap-2 min-w-0">
                                    <ClockIcon className="h-4 w-4 text-gray-400 shrink-0" />
                                    <span className="font-medium text-gray-900 dark:text-white">
                                        {auditEventLabel(e.event_type)}
                                    </span>
                                    {e.description && (
                                        <span className="text-xs text-gray-500 dark:text-gray-400 truncate">
                                            {e.description}
                                        </span>
                                    )}
                                    {e.actor_type === 'machine_identity' && (
                                        <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-blue-100 text-blue-800 dark:bg-blue-900/40 dark:text-blue-300">
                                            machine
                                        </span>
                                    )}
                                </div>
                                <span
                                    className="text-xs text-gray-500 dark:text-gray-400 whitespace-nowrap"
                                    title={new Date(e.timestamp).toLocaleString()}
                                >
                                    {relativeFromNow(e.timestamp)}
                                </span>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* Risk Score */}
            {risk && (
                <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
                    <div className="flex items-center justify-between mb-4">
                        <h3 className="text-lg font-medium text-gray-900 dark:text-white flex items-center">
                            <ShieldExclamationIcon className="h-5 w-5 mr-2" />
                            Risk Score
                        </h3>
                        <div className="flex items-center gap-3">
                            <span
                                className="text-2xl font-bold tabular-nums"
                                style={{ color: RISK_BAND_STYLE[risk.band].color }}
                            >
                                {risk.score}
                                <span className="text-sm font-normal text-gray-400"> / 100</span>
                            </span>
                            <span
                                className="px-2.5 py-1 rounded-full text-xs font-semibold"
                                style={{
                                    color: RISK_BAND_STYLE[risk.band].color,
                                    backgroundColor: `${RISK_BAND_STYLE[risk.band].color}1a`,
                                }}
                            >
                                {RISK_BAND_STYLE[risk.band].label}
                            </span>
                        </div>
                    </div>
                    <div className="space-y-3">
                        {risk.factors.map((f) => (
                            <div key={f.key} className="space-y-1">
                                <div className="flex items-center justify-between text-sm">
                                    <span className="text-gray-700 dark:text-gray-300">
                                        {f.label}
                                        <span className="text-gray-400 dark:text-gray-500 ml-2">
                                            {Math.round(f.weight * 100)}%
                                        </span>
                                    </span>
                                    <span className="text-xs text-gray-500 dark:text-gray-400">{f.detail}</span>
                                </div>
                                <div className="h-1.5 rounded-full overflow-hidden bg-gray-100 dark:bg-gray-700">
                                    <div
                                        className="h-full rounded-full transition-all duration-700"
                                        style={{ width: `${f.score}%`, backgroundColor: factorColor(f.score) }}
                                    />
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* Dependency graph (ADR-052) */}
            <SecretDependenciesSection secret={secret} />

            {/* Tags */}
            {secret.tags.length > 0 && (
                <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
                    <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4 flex items-center">
                        <TagIcon className="h-5 w-5 mr-2" />
                        Tags
                    </h3>
                    <div className="flex flex-wrap gap-2">
                        {secret.tags.map((tag) => (
                            <span
                                key={tag}
                                className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200"
                            >
                                {tag}
                            </span>
                        ))}
                    </div>
                </div>
            )}

            {/* Metadata */}
            {Object.keys(secret.metadata).length > 0 && (
                <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
                    <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">Metadata</h3>
                    <div className="space-y-3">
                        {Object.entries(secret.metadata).map(([key, value]) => (
                            <div key={key} className="flex items-start">
                                <div className="w-1/3 text-sm font-medium text-gray-500 dark:text-gray-400">{key}</div>
                                <div className="w-2/3 text-sm text-gray-900 dark:text-white">{value}</div>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* Sharing Information */}
            {secret.isShared && (
                <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
                    <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4 flex items-center">
                        <ShareIcon className="h-5 w-5 mr-2" />
                        Sharing
                    </h3>
                    <div className="flex items-center justify-between">
                        <div>
                            <p className="text-sm text-gray-900 dark:text-white">
                                This secret is shared with <span className="font-medium">{secret.shareCount}</span>{' '}
                                recipients
                            </p>
                            <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                                Click "Share" to manage sharing permissions
                            </p>
                        </div>
                        <Button variant="outline" size="sm" onClick={() => onShare?.(secret)}>
                            Manage Shares
                        </Button>
                    </div>
                </div>
            )}

            {/* Permissions */}
            {secret.permissions.length > 0 && (
                <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
                    <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">Permissions</h3>
                    <div className="flex flex-wrap gap-2">
                        {secret.permissions.map((permission) => (
                            <span
                                key={permission}
                                className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200"
                            >
                                {permission}
                            </span>
                        ))}
                    </div>
                </div>
            )}

            {/* Actions */}
            <div className="flex items-center justify-end space-x-3 pt-6 border-t border-gray-200 dark:border-gray-700">
                <Button variant="outline" onClick={onClose}>
                    Close
                </Button>
            </div>

            {/* Rotate modal */}
            <Modal isOpen={showRotate} onClose={closeRotate} title={`Rotate ${secret.name}`} size="md">
                <div className="space-y-4">
                    <p className="text-sm text-gray-500 dark:text-gray-400">
                        Enter the new value for this secret. Rotating stores a new version (the previous value is kept
                        in history) and records the rotation timestamp.
                    </p>

                    <Textarea
                        label="New value"
                        value={rotateValue}
                        onChange={(e) => setRotateValue(e.target.value)}
                        placeholder="New secret value"
                        rows={4}
                        autoComplete="off"
                        disabled={rotateMutation.isPending}
                    />

                    {rotateMutation.isError && (
                        <Alert
                            type="error"
                            title="Rotation failed"
                            message="The secret could not be rotated. Please try again."
                        />
                    )}

                    <div className="flex items-center justify-end space-x-3 pt-2">
                        <Button variant="outline" onClick={closeRotate} disabled={rotateMutation.isPending}>
                            Cancel
                        </Button>
                        <Button
                            variant="default"
                            onClick={handleRotate}
                            disabled={!rotateValue.trim() || rotateMutation.isPending}
                        >
                            {rotateMutation.isPending ? (
                                <>
                                    <Spinner size="sm" />
                                    <span className="ml-2">Rotating…</span>
                                </>
                            ) : (
                                <>
                                    <ArrowPathIcon className="h-4 w-4 mr-2" />
                                    Rotate secret
                                </>
                            )}
                        </Button>
                    </div>
                </div>
            </Modal>
        </div>
    );
};
