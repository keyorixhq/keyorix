import React, { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import {
    DevicePhoneMobileIcon,
    QrCodeIcon,
    KeyIcon,
    CheckCircleIcon,
    ExclamationTriangleIcon,
    ClipboardDocumentIcon
} from '@heroicons/react/24/outline';
import { useForm } from '../../store/formStore';
import { apiService } from '../../services/api';
import { Button } from '../ui/Button';
import { Input } from '../ui/Input';
import { Modal } from '../ui/Modal';
import { Alert } from '../ui/Alert';
import { Loading } from '../ui/Loading';

interface TwoFactorSetupProps {
    isOpen: boolean;
    onClose: () => void;
    onSuccess?: () => void;
}

interface TwoFactorSetupData {
    secret: string;
    qrCodeUrl: string;
    backupCodes: string[];
}

const FORM_ID = 'two-factor-setup';

export const TwoFactorSetup: React.FC<TwoFactorSetupProps> = ({
    isOpen,
    onClose,
    onSuccess
}) => {
    const [step, setStep] = useState<'setup' | 'verify' | 'backup' | 'complete'>('setup');
    const [setupData, setSetupData] = useState<TwoFactorSetupData | null>(null);
    const [backupCodesCopied, setBackupCodesCopied] = useState(false);
    const form = useForm(FORM_ID);

    // Initialize form
    React.useEffect(() => {
        if (isOpen) {
            form.initialize({
                verificationCode: '',
            });
            setStep('setup');
            setSetupData(null);
            setBackupCodesCopied(false);
        } else {
            form.destroy();
        }
    }, [isOpen, form]);

    // Generate 2FA setup data
    const generateSetupMutation = useMutation({
        mutationFn: async (): Promise<TwoFactorSetupData> => {
            // Mock 2FA setup data - in real app this would come from the API
            await new Promise(resolve => setTimeout(resolve, 1000));

            return {
                secret: 'JBSWY3DPEHPK3PXP',
                qrCodeUrl: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==',
                backupCodes: [
                    '12345-67890',
                    '23456-78901',
                    '34567-89012',
                    '45678-90123',
                    '56789-01234',
                    '67890-12345',
                    '78901-23456',
                    '89012-34567',
                ]
            };
        },
        onSuccess: (data) => {
            setSetupData(data);
            setStep('verify');
        },
    });

    // Verify 2FA code
    const verifyCodeMutation = useMutation({
        mutationFn: async (code: string) => {
            // Mock verification - in real app this would call the API
            await new Promise(resolve => setTimeout(resolve, 1000));

            if (code !== '123456') {
                throw new Error('Invalid verification code');
            }

            return true;
        },
        onSuccess: () => {
            setStep('backup');
        },
    });

    // Complete 2FA setup
    const completeMutation = useMutation({
        mutationFn: async () => {
            // Mock completion - in real app this would call the API
            await new Promise(resolve => setTimeout(resolve, 500));
            return true;
        },
        onSuccess: () => {
            setStep('complete');
            setTimeout(() => {
                onSuccess?.();
                onClose();
            }, 2000);
        },
    });

    const handleGenerateSetup = () => {
        generateSetupMutation.mutate();
    };

    const handleVerifyCode = async (e: React.FormEvent) => {
        e.preventDefault();
        const values = form.getValues();

        if (!values.verificationCode || values.verificationCode.length !== 6) {
            form.setErrors({ verificationCode: 'Please enter a 6-digit code' });
            return;
        }

        form.setSubmitting(true);
        try {
            await verifyCodeMutation.mutateAsync(values.verificationCode);
        } catch (error) {
            form.setErrors({ verificationCode: 'Invalid verification code' });
        } finally {
            form.setSubmitting(false);
        }
    };

    const handleCopyBackupCodes = async () => {
        if (setupData?.backupCodes) {
            try {
                await navigator.clipboard.writeText(setupData.backupCodes.join('\n'));
                setBackupCodesCopied(true);
            } catch (error) {
                console.error('Failed to copy backup codes:', error);
            }
        }
    };

    const handleComplete = () => {
        completeMutation.mutate();
    };

    const values = form.getValues();
    const errors = form.getErrors();
    const isSubmitting = form.isSubmitting();

    const renderStepContent = () => {
        switch (step) {
            case 'setup':
                return (
                    <div className="text-center space-y-6">
                        <div className="mx-auto w-16 h-16 bg-blue-100 dark:bg-blue-900/20 rounded-full flex items-center justify-center">
                            <DevicePhoneMobileIcon className="h-8 w-8 text-blue-600 dark:text-blue-400" />
                        </div>

                        <div>
                            <h3 className="text-lg font-medium text-gray-900 dark:text-white">
                                Set Up Two-Factor Authentication
                            </h3>
                            <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">
                                Add an extra layer of security to your account by requiring a verification code from your phone.
                            </p>
                        </div>

                        <div className="bg-blue-50 dark:bg-blue-900/20 rounded-lg p-4">
                            <h4 className="text-sm font-medium text-blue-900 dark:text-blue-100 mb-2">
                                Before you start:
                            </h4>
                            <ul className="text-sm text-blue-700 dark:text-blue-200 space-y-1 text-left">
                                <li>• Install an authenticator app (Google Authenticator, Authy, etc.)</li>
                                <li>• Have your phone ready to scan a QR code</li>
                                <li>• Save the backup codes in a secure location</li>
                            </ul>
                        </div>

                        {generateSetupMutation.error && (
                            <Alert
                                type="error"
                                title="Setup Failed"
                                message="Failed to generate 2FA setup. Please try again."
                            />
                        )}

                        <Button
                            onClick={handleGenerateSetup}
                            disabled={generateSetupMutation.isPending}
                            className="w-full"
                        >
                            {generateSetupMutation.isPending && <Loading size="sm" className="mr-2" />}
                            <QrCodeIcon className="h-4 w-4 mr-2" />
                            Generate Setup Code
                        </Button>
                    </div>
                );

            case 'verify':
                return (
                    <div className="space-y-6">
                        <div className="text-center">
                            <h3 className="text-lg font-medium text-gray-900 dark:text-white">
                                Scan QR Code
                            </h3>
                            <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">
                                Scan this QR code with your authenticator app, then enter the verification code.
                            </p>
                        </div>

                        {/* QR Code */}
                        <div className="flex justify-center">
                            <div className="bg-white p-4 rounded-lg border border-gray-200">
                                <img
                                    src={setupData?.qrCodeUrl}
                                    alt="2FA QR Code"
                                    className="w-48 h-48"
                                />
                            </div>
                        </div>

                        {/* Manual Setup */}
                        <div className="bg-gray-50 dark:bg-gray-700 rounded-lg p-4">
                            <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-2">
                                Can't scan? Enter this code manually:
                            </h4>
                            <div className="flex items-center space-x-2">
                                <code className="flex-1 text-sm font-mono bg-white dark:bg-gray-800 px-3 py-2 rounded border">
                                    {setupData?.secret}
                                </code>
                                <Button
                                    variant="outline"
                                    size="sm"
                                    onClick={() => navigator.clipboard.writeText(setupData?.secret || '')}
                                >
                                    <ClipboardDocumentIcon className="h-4 w-4" />
                                </Button>
                            </div>
                        </div>

                        {/* Verification Form */}
                        <form onSubmit={handleVerifyCode} className="space-y-4">
                            <div>
                                <Input
                                    label="Verification Code"
                                    type="text"
                                    value={values.verificationCode || ''}
                                    onChange={(e) => form.setValues({ verificationCode: e.target.value.replace(/\D/g, '').slice(0, 6) })}
                                    error={errors.verificationCode}
                                    placeholder="123456"
                                    className="text-center text-lg tracking-widest"
                                    maxLength={6}
                                    required
                                />
                                <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                                    Enter the 6-digit code from your authenticator app
                                </p>
                            </div>

                            {verifyCodeMutation.error && (
                                <Alert
                                    type="error"
                                    title="Verification Failed"
                                    message={verifyCodeMutation.error.message}
                                />
                            )}

                            <div className="flex space-x-3">
                                <Button
                                    type="button"
                                    variant="outline"
                                    onClick={() => setStep('setup')}
                                    className="flex-1"
                                >
                                    Back
                                </Button>
                                <Button
                                    type="submit"
                                    disabled={isSubmitting || !values.verificationCode || values.verificationCode.length !== 6}
                                    className="flex-1"
                                >
                                    {isSubmitting && <Loading size="sm" className="mr-2" />}
                                    Verify Code
                                </Button>
                            </div>
                        </form>
                    </div>
                );

            case 'backup':
                return (
                    <div className="space-y-6">
                        <div className="text-center">
                            <div className="mx-auto w-16 h-16 bg-yellow-100 dark:bg-yellow-900/20 rounded-full flex items-center justify-center">
                                <ExclamationTriangleIcon className="h-8 w-8 text-yellow-600 dark:text-yellow-400" />
                            </div>
                            <h3 className="mt-4 text-lg font-medium text-gray-900 dark:text-white">
                                Save Your Backup Codes
                            </h3>
                            <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">
                                Store these backup codes in a safe place. You can use them to access your account if you lose your phone.
                            </p>
                        </div>

                        <div className="bg-gray-50 dark:bg-gray-700 rounded-lg p-4">
                            <div className="flex items-center justify-between mb-3">
                                <h4 className="text-sm font-medium text-gray-900 dark:text-white">
                                    Backup Codes
                                </h4>
                                <Button
                                    variant="outline"
                                    size="sm"
                                    onClick={handleCopyBackupCodes}
                                >
                                    <ClipboardDocumentIcon className="h-4 w-4 mr-2" />
                                    {backupCodesCopied ? 'Copied!' : 'Copy All'}
                                </Button>
                            </div>
                            <div className="grid grid-cols-2 gap-2">
                                {setupData?.backupCodes.map((code, index) => (
                                    <code
                                        key={index}
                                        className="text-sm font-mono bg-white dark:bg-gray-800 px-3 py-2 rounded border text-center"
                                    >
                                        {code}
                                    </code>
                                ))}
                            </div>
                        </div>

                        <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4">
                            <div className="flex items-start">
                                <ExclamationTriangleIcon className="h-5 w-5 text-red-500 mt-0.5 mr-3" />
                                <div>
                                    <h4 className="text-sm font-medium text-red-900 dark:text-red-100">
                                        Important Security Notice
                                    </h4>
                                    <ul className="mt-1 text-sm text-red-700 dark:text-red-200 space-y-1">
                                        <li>• Each backup code can only be used once</li>
                                        <li>• Store these codes in a secure password manager</li>
                                        <li>• Don't share these codes with anyone</li>
                                        <li>• You won't be able to see these codes again</li>
                                    </ul>
                                </div>
                            </div>
                        </div>

                        <div className="flex space-x-3">
                            <Button
                                type="button"
                                variant="outline"
                                onClick={() => setStep('verify')}
                                className="flex-1"
                            >
                                Back
                            </Button>
                            <Button
                                onClick={handleComplete}
                                disabled={completeMutation.isPending}
                                className="flex-1"
                            >
                                {completeMutation.isPending && <Loading size="sm" className="mr-2" />}
                                <KeyIcon className="h-4 w-4 mr-2" />
                                Complete Setup
                            </Button>
                        </div>
                    </div>
                );

            case 'complete':
                return (
                    <div className="text-center space-y-6">
                        <div className="mx-auto w-16 h-16 bg-green-100 dark:bg-green-900/20 rounded-full flex items-center justify-center">
                            <CheckCircleIcon className="h-8 w-8 text-green-600 dark:text-green-400" />
                        </div>

                        <div>
                            <h3 className="text-lg font-medium text-gray-900 dark:text-white">
                                Two-Factor Authentication Enabled!
                            </h3>
                            <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">
                                Your account is now protected with two-factor authentication. You'll need to enter a code from your authenticator app when signing in.
                            </p>
                        </div>

                        <div className="bg-green-50 dark:bg-green-900/20 rounded-lg p-4">
                            <h4 className="text-sm font-medium text-green-900 dark:text-green-100 mb-2">
                                What's next?
                            </h4>
                            <ul className="text-sm text-green-700 dark:text-green-200 space-y-1 text-left">
                                <li>• Your backup codes have been saved</li>
                                <li>• Test signing in with your new setup</li>
                                <li>• Consider enabling 2FA on other accounts</li>
                            </ul>
                        </div>
                    </div>
                );

            default:
                return null;
        }
    };

    return (
        <Modal
            isOpen={isOpen}
            onClose={onClose}
            title="Two-Factor Authentication Setup"
            size="lg"
        >
            <div className="p-6">
                {/* Progress Indicator */}
                <div className="mb-8">
                    <div className="flex items-center justify-between">
                        {['setup', 'verify', 'backup', 'complete'].map((stepName, index) => (
                            <div
                                key={stepName}
                                className={`flex items-center ${index < 3 ? 'flex-1' : ''}`}
                            >
                                <div
                                    className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium ${step === stepName
                                            ? 'bg-blue-600 text-white'
                                            : ['setup', 'verify', 'backup', 'complete'].indexOf(step) > index
                                                ? 'bg-green-600 text-white'
                                                : 'bg-gray-200 text-gray-600 dark:bg-gray-700 dark:text-gray-400'
                                        }`}
                                >
                                    {['setup', 'verify', 'backup', 'complete'].indexOf(step) > index ? (
                                        <CheckCircleIcon className="h-5 w-5" />
                                    ) : (
                                        index + 1
                                    )}
                                </div>
                                {index < 3 && (
                                    <div
                                        className={`flex-1 h-1 mx-2 ${['setup', 'verify', 'backup', 'complete'].indexOf(step) > index
                                                ? 'bg-green-600'
                                                : 'bg-gray-200 dark:bg-gray-700'
                                            }`}
                                    />
                                )}
                            </div>
                        ))}
                    </div>
                </div>

                {renderStepContent()}
            </div>
        </Modal>
    );
};