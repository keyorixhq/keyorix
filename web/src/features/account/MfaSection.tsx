import React, { useState } from 'react';
import {
    DevicePhoneMobileIcon,
    ShieldCheckIcon,
    ClipboardDocumentIcon,
    CheckIcon,
    ExclamationTriangleIcon,
} from '@heroicons/react/24/outline';
import { Button } from '../../components/ui/Button';
import { Input } from '../../components/ui/Input';
import { Alert } from '../../components/ui/Alert';
import { Spinner } from '../../components/ui/Loading';
import { Modal } from '../../components/ui/Modal';
import { copyToClipboard } from '../../utils';
import { useMfaRecoveryStatus, useEnrollMfa, useActivateMfa, useDisableMfa, useRegenerateRecoveryCodes } from './index';
import { useAutoClearOnIdle } from '../../hooks/useAutoClearOnIdle';

// LOW_CODES_THRESHOLD is when we nudge the user to regenerate recovery codes.
const LOW_CODES_THRESHOLD = 3;

function errMessage(e: unknown, fallback: string): string {
    return (
        (e as { response?: { data?: { message?: string } }; message?: string })?.response?.data?.message ||
        (e as Error)?.message ||
        fallback
    );
}

// RecoveryCodes renders the one-time codes with a copy-all control. The codes are
// shown once after activation/regeneration and never retrievable again.
const RecoveryCodes: React.FC<{ codes: string[] }> = ({ codes }) => {
    const [copied, setCopied] = useState(false);
    const copy = async () => {
        await copyToClipboard(codes.join('\n'));
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
    };
    return (
        <div className="space-y-3">
            <Alert
                type="warning"
                title="Save your recovery codes"
                message="Store these somewhere safe. Each works once if you lose your authenticator, and they will not be shown again."
            />
            <div
                className="grid grid-cols-2 gap-2 rounded-lg p-4 font-mono text-sm"
                style={{ backgroundColor: 'var(--bg-subtle)', border: '1px solid var(--border)' }}
            >
                {codes.map((c) => (
                    <span key={c} style={{ color: 'var(--text-primary)' }}>
                        {c}
                    </span>
                ))}
            </div>
            <Button variant="outline" size="sm" onClick={copy}>
                {copied ? <CheckIcon className="h-4 w-4 mr-2" /> : <ClipboardDocumentIcon className="h-4 w-4 mr-2" />}
                {copied ? 'Copied' : 'Copy all'}
            </Button>
        </div>
    );
};

// EnrollModal walks enrol → activate → show recovery codes.
const EnrollModal: React.FC<{ isOpen: boolean; onClose: () => void }> = ({ isOpen, onClose }) => {
    const enroll = useEnrollMfa();
    const activate = useActivateMfa();
    const [secret, setSecret] = useState('');
    const [uri, setUri] = useState('');
    const [code, setCode] = useState('');
    const [codes, setCodes] = useState<string[] | null>(null);
    const [error, setError] = useState('');

    // Begin enrolment the first time the modal opens.
    React.useEffect(() => {
        if (isOpen && !secret && !enroll.isPending && !codes) {
            enroll.mutate(undefined, {
                onSuccess: (d) => {
                    setSecret(d.secret);
                    setUri(d.otpauth_uri);
                },
                onError: (e) => setError(errMessage(e, 'Could not begin enrolment.')),
            });
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [isOpen]);

    const reset = () => {
        setSecret('');
        setUri('');
        setCode('');
        setCodes(null);
        setError('');
    };
    const close = () => {
        reset();
        onClose();
    };

    // G28: the recovery codes otherwise stay rendered indefinitely until the user
    // explicitly clicks Done/Cancel — auto-clear (close the modal) on idle, tab
    // backgrounding, or window blur too.
    useAutoClearOnIdle(close, codes !== null);

    const submit = (e: React.SubmitEvent<HTMLFormElement>) => {
        e.preventDefault();
        setError('');
        activate.mutate(code, {
            onSuccess: (newCodes) => setCodes(newCodes),
            onError: (err) => setError(errMessage(err, 'Invalid code. Try again.')),
        });
    };

    return (
        <Modal isOpen={isOpen} onClose={close} title="Set up two-factor authentication" size="md">
            {codes ? (
                <div className="space-y-4">
                    <RecoveryCodes codes={codes} />
                    <div className="flex justify-end">
                        <Button onClick={close}>Done</Button>
                    </div>
                </div>
            ) : (
                <form onSubmit={submit} className="space-y-4">
                    {error && <Alert type="error" message={error} />}
                    <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
                        Add this key to your authenticator app (Google Authenticator, 1Password, …), then enter the
                        6-digit code it shows.
                    </p>
                    {enroll.isPending && !secret ? (
                        <div className="flex justify-center py-6">
                            <Spinner />
                        </div>
                    ) : (
                        <>
                            <div>
                                <p
                                    className="block text-sm font-medium mb-1"
                                    style={{ color: 'var(--text-secondary)' }}
                                >
                                    Setup key
                                </p>
                                <code
                                    className="block break-all rounded-md p-3 text-sm"
                                    style={{
                                        backgroundColor: 'var(--bg-subtle)',
                                        border: '1px solid var(--border)',
                                        color: 'var(--text-primary)',
                                    }}
                                >
                                    {secret}
                                </code>
                                {uri && /^otpauth:\/\//i.test(uri) && (
                                    <a
                                        href={uri}
                                        className="mt-1 inline-block text-xs"
                                        style={{ color: 'var(--accent-text)' }}
                                    >
                                        Open in authenticator app
                                    </a>
                                )}
                            </div>
                            <Input
                                label="6-digit code"
                                inputMode="numeric"
                                autoComplete="one-time-code"
                                placeholder="123456"
                                value={code}
                                onChange={(e) => setCode(e.target.value)}
                            />
                            <div className="flex justify-end gap-2">
                                <Button type="button" variant="outline" onClick={close}>
                                    Cancel
                                </Button>
                                <Button type="submit" disabled={activate.isPending || code.length < 6}>
                                    {activate.isPending && <Spinner size="sm" className="mr-2" />}
                                    Verify &amp; enable
                                </Button>
                            </div>
                        </>
                    )}
                </form>
            )}
        </Modal>
    );
};

// ReauthModal collects a current code or password and runs a sensitive action
// (disable, or regenerate recovery codes). When the action returns codes, they are
// displayed once.
const ReauthModal: React.FC<{
    isOpen: boolean;
    onClose: () => void;
    title: string;
    confirmLabel: string;
    confirmVariant?: 'default' | 'destructive';
    intro: string;
    isPending: boolean;
    run: (proof: { code?: string; password?: string }) => Promise<string[] | void>;
}> = ({ isOpen, onClose, title, confirmLabel, confirmVariant = 'default', intro, isPending, run }) => {
    const [secret, setSecret] = useState('');
    const [codes, setCodes] = useState<string[] | null>(null);
    const [error, setError] = useState('');

    const close = () => {
        setSecret('');
        setCodes(null);
        setError('');
        onClose();
    };

    // G28: the recovery codes otherwise stay rendered indefinitely until the user
    // explicitly clicks Done/Cancel — auto-clear (close the modal) on idle, tab
    // backgrounding, or window blur too.
    useAutoClearOnIdle(close, codes !== null);

    const submit = async (e: React.SubmitEvent<HTMLFormElement>) => {
        e.preventDefault();
        setError('');
        // The same field accepts a 6-digit TOTP code or the account password.
        const proof = /^\d{6}$/.test(secret.trim()) ? { code: secret.trim() } : { password: secret };
        try {
            const result = await run(proof);
            if (result && result.length) {
                setCodes(result);
            } else {
                close();
            }
        } catch (err) {
            setError(errMessage(err, 'Invalid code or password.'));
        }
    };

    return (
        <Modal isOpen={isOpen} onClose={close} title={title} size="md">
            {codes ? (
                <div className="space-y-4">
                    <RecoveryCodes codes={codes} />
                    <div className="flex justify-end">
                        <Button onClick={close}>Done</Button>
                    </div>
                </div>
            ) : (
                <form onSubmit={submit} className="space-y-4">
                    {error && <Alert type="error" message={error} />}
                    <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
                        {intro}
                    </p>
                    <Input
                        label="Authenticator code or password"
                        type="password"
                        autoComplete="off"
                        placeholder="123456 or your password"
                        value={secret}
                        onChange={(e) => setSecret(e.target.value)}
                    />
                    <div className="flex justify-end gap-2">
                        <Button type="button" variant="outline" onClick={close}>
                            Cancel
                        </Button>
                        <Button type="submit" variant={confirmVariant} disabled={isPending || !secret}>
                            {isPending && <Spinner size="sm" className="mr-2" />}
                            {confirmLabel}
                        </Button>
                    </div>
                </form>
            )}
        </Modal>
    );
};

// MfaSection is the Profile → Security two-factor block: it shows enable/enrol when
// MFA is off, and status + recovery-code management + disable when it is on.
export const MfaSection: React.FC = () => {
    const { data: status, isLoading, isError } = useMfaRecoveryStatus();
    const disable = useDisableMfa();
    const regenerate = useRegenerateRecoveryCodes();
    const [enrolling, setEnrolling] = useState(false);
    const [regenOpen, setRegenOpen] = useState(false);
    const [disableOpen, setDisableOpen] = useState(false);

    const enabled = (status?.total ?? 0) > 0;
    const remaining = status?.remaining ?? 0;
    const total = status?.total ?? 0;
    const lowCodes = enabled && remaining <= LOW_CODES_THRESHOLD;

    const enabledButton = enabled ? (
        <Button variant="destructive" size="sm" onClick={() => setDisableOpen(true)}>
            Disable
        </Button>
    ) : (
        <Button size="sm" onClick={() => setEnrolling(true)}>
            Enable
        </Button>
    );

    return (
        <div className="pt-8 border-t" style={{ borderColor: 'var(--border)' }}>
            <h3 className="text-lg font-medium" style={{ color: 'var(--text-primary)' }}>
                Two-Factor Authentication
            </h3>

            <div
                className="mt-4 rounded-lg p-5"
                style={{ backgroundColor: 'var(--bg-subtle)', border: '1px solid var(--border)' }}
            >
                <div className="flex items-center justify-between">
                    <div className="flex items-center">
                        <DevicePhoneMobileIcon className="h-7 w-7 mr-4" style={{ color: 'var(--text-muted)' }} />
                        <div>
                            <h4
                                className="text-sm font-medium flex items-center gap-2"
                                style={{ color: 'var(--text-primary)' }}
                            >
                                Authenticator App
                                {enabled && (
                                    <span
                                        className="text-xs font-medium px-2 py-0.5 rounded-full inline-flex items-center gap-1"
                                        style={{
                                            color: 'var(--accent-text)',
                                            backgroundColor: 'var(--accent-subtle)',
                                        }}
                                    >
                                        <ShieldCheckIcon className="h-3.5 w-3.5" />
                                        Enabled
                                    </span>
                                )}
                            </h4>
                            <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
                                {enabled
                                    ? `${remaining} of ${total} recovery codes remaining`
                                    : 'Add a time-based one-time code (TOTP) as a second factor at login.'}
                            </p>
                        </div>
                    </div>

                    {isLoading ? <Spinner size="sm" /> : enabledButton}
                </div>

                {isError && (
                    <p className="mt-3 text-sm" style={{ color: 'var(--text-muted)' }}>
                        Could not load two-factor status.
                    </p>
                )}

                {enabled && (
                    <div
                        className="mt-4 pt-4 flex items-center justify-between"
                        style={{ borderTop: '1px solid var(--border)' }}
                    >
                        <div
                            className="flex items-center gap-2 text-sm"
                            style={{ color: lowCodes ? 'var(--warning-text, #b45309)' : 'var(--text-muted)' }}
                        >
                            {lowCodes && <ExclamationTriangleIcon className="h-4 w-4" />}
                            {lowCodes
                                ? 'You are running low on recovery codes.'
                                : 'Recovery codes let you sign in if you lose your device.'}
                        </div>
                        <Button variant="outline" size="sm" onClick={() => setRegenOpen(true)}>
                            Regenerate codes
                        </Button>
                    </div>
                )}
            </div>

            <EnrollModal isOpen={enrolling} onClose={() => setEnrolling(false)} />

            <ReauthModal
                isOpen={regenOpen}
                onClose={() => setRegenOpen(false)}
                title="Regenerate recovery codes"
                confirmLabel="Regenerate"
                intro="This replaces all of your existing recovery codes with a new set. Confirm with a current authenticator code or your password."
                isPending={regenerate.isPending}
                run={(proof) => regenerate.mutateAsync(proof)}
            />

            <ReauthModal
                isOpen={disableOpen}
                onClose={() => setDisableOpen(false)}
                title="Disable two-factor authentication"
                confirmLabel="Disable 2FA"
                confirmVariant="destructive"
                intro="Your account will be protected by your password only. Confirm with a current authenticator code or your password."
                isPending={disable.isPending}
                run={async (proof) => {
                    await disable.mutateAsync(proof);
                }}
            />
        </div>
    );
};
