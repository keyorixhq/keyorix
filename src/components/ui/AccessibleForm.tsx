import React from 'react';
import { useAriaAttributes, useScreenReader } from '../../hooks/useAccessibility';
import { useTranslation } from '../../lib/i18n';

interface AccessibleFormProps {
    children: React.ReactNode;
    onSubmit: (e: React.FormEvent) => void;
    title?: string;
    description?: string;
    className?: string;
    noValidate?: boolean;
}

export const AccessibleForm: React.FC<AccessibleFormProps> = ({
    children,
    onSubmit,
    title,
    description,
    className = '',
    noValidate = true,
}) => {
    const { generateId, getAriaProps } = useAriaAttributes();
    const { announce } = useScreenReader();
    const { t } = useTranslation();

    const formId = React.useMemo(() => generateId('form'), [generateId]);
    const titleId = React.useMemo(() => generateId('form-title'), [generateId]);
    const descriptionId = React.useMemo(() => generateId('form-description'), [generateId]);

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();

        // Announce form submission to screen readers
        announce(t('accessibility.loading'));

        onSubmit(e);
    };

    return (
        <form
            id={formId}
            onSubmit={handleSubmit}
            noValidate={noValidate}
            className={className}
            {...getAriaProps({
                labelledBy: title ? titleId : undefined,
                describedBy: description ? descriptionId : undefined,
            })}
        >
            {title && (
                <h2 id={titleId} className="text-lg font-medium text-gray-900 dark:text-white mb-2">
                    {title}
                </h2>
            )}

            {description && (
                <p id={descriptionId} className="text-sm text-gray-600 dark:text-gray-400 mb-6">
                    {description}
                </p>
            )}

            {children}
        </form>
    );
};

interface AccessibleFieldsetProps {
    legend: string;
    children: React.ReactNode;
    className?: string;
    required?: boolean;
}

export const AccessibleFieldset: React.FC<AccessibleFieldsetProps> = ({
    legend,
    children,
    className = '',
    required = false,
}) => {
    const { t } = useTranslation();

    return (
        <fieldset className={`border border-gray-200 dark:border-gray-700 rounded-lg p-4 ${className}`}>
            <legend className="text-sm font-medium text-gray-900 dark:text-white px-2">
                {legend}
                {required && (
                    <span className="text-red-500 ml-1" aria-label={t('accessibility.required_field')}>
                        *
                    </span>
                )}
            </legend>
            {children}
        </fieldset>
    );
};

interface AccessibleInputProps extends Omit<React.InputHTMLAttributes<HTMLInputElement>, 'id'> {
    label: string;
    error?: string;
    helpText?: string;
    required?: boolean;
    showRequiredIndicator?: boolean;
}

export const AccessibleInput: React.FC<AccessibleInputProps> = ({
    label,
    error,
    helpText,
    required = false,
    showRequiredIndicator = true,
    className = '',
    ...inputProps
}) => {
    const { generateId, getAriaProps } = useAriaAttributes();
    const { t } = useTranslation();

    const inputId = React.useMemo(() => generateId('input'), [generateId]);
    const errorId = React.useMemo(() => generateId('error'), [generateId]);
    const helpId = React.useMemo(() => generateId('help'), [generateId]);

    const describedBy = [
        error ? errorId : null,
        helpText ? helpId : null,
    ].filter(Boolean).join(' ');

    return (
        <div className="space-y-2">
            <label
                htmlFor={inputId}
                className="block text-sm font-medium text-gray-700 dark:text-gray-300"
            >
                {label}
                {required && showRequiredIndicator && (
                    <span className="text-red-500 ml-1" aria-label={t('accessibility.required_field')}>
                        *
                    </span>
                )}
            </label>

            <input
                id={inputId}
                className={`
          block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 
          rounded-md shadow-sm placeholder-gray-400 dark:placeholder-gray-500
          focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500
          dark:bg-gray-700 dark:text-white
          ${error ? 'border-red-300 focus:ring-red-500 focus:border-red-500' : ''}
          ${className}
        `}
                {...getAriaProps({
                    required,
                    invalid: !!error,
                    describedBy: describedBy || undefined,
                })}
                {...inputProps}
            />

            {helpText && (
                <p id={helpId} className="text-sm text-gray-500 dark:text-gray-400">
                    {helpText}
                </p>
            )}

            {error && (
                <p
                    id={errorId}
                    className="text-sm text-red-600 dark:text-red-400"
                    role="alert"
                    aria-live="polite"
                >
                    {error}
                </p>
            )}
        </div>
    );
};

interface AccessibleSelectProps extends Omit<React.SelectHTMLAttributes<HTMLSelectElement>, 'id'> {
    label: string;
    options: { value: string; label: string; disabled?: boolean }[];
    error?: string;
    helpText?: string;
    required?: boolean;
    showRequiredIndicator?: boolean;
    placeholder?: string;
}

export const AccessibleSelect: React.FC<AccessibleSelectProps> = ({
    label,
    options,
    error,
    helpText,
    required = false,
    showRequiredIndicator = true,
    placeholder,
    className = '',
    ...selectProps
}) => {
    const { generateId, getAriaProps } = useAriaAttributes();
    const { t } = useTranslation();

    const selectId = React.useMemo(() => generateId('select'), [generateId]);
    const errorId = React.useMemo(() => generateId('error'), [generateId]);
    const helpId = React.useMemo(() => generateId('help'), [generateId]);

    const describedBy = [
        error ? errorId : null,
        helpText ? helpId : null,
    ].filter(Boolean).join(' ');

    return (
        <div className="space-y-2">
            <label
                htmlFor={selectId}
                className="block text-sm font-medium text-gray-700 dark:text-gray-300"
            >
                {label}
                {required && showRequiredIndicator && (
                    <span className="text-red-500 ml-1" aria-label={t('accessibility.required_field')}>
                        *
                    </span>
                )}
            </label>

            <select
                id={selectId}
                className={`
          block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 
          rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 
          focus:border-blue-500 dark:bg-gray-700 dark:text-white
          ${error ? 'border-red-300 focus:ring-red-500 focus:border-red-500' : ''}
          ${className}
        `}
                {...getAriaProps({
                    required,
                    invalid: !!error,
                    describedBy: describedBy || undefined,
                })}
                {...selectProps}
            >
                {placeholder && (
                    <option value="" disabled>
                        {placeholder}
                    </option>
                )}
                {options.map((option) => (
                    <option
                        key={option.value}
                        value={option.value}
                        disabled={option.disabled}
                    >
                        {option.label}
                    </option>
                ))}
            </select>

            {helpText && (
                <p id={helpId} className="text-sm text-gray-500 dark:text-gray-400">
                    {helpText}
                </p>
            )}

            {error && (
                <p
                    id={errorId}
                    className="text-sm text-red-600 dark:text-red-400"
                    role="alert"
                    aria-live="polite"
                >
                    {error}
                </p>
            )}
        </div>
    );
};

interface AccessibleTextareaProps extends Omit<React.TextareaHTMLAttributes<HTMLTextAreaElement>, 'id'> {
    label: string;
    error?: string;
    helpText?: string;
    required?: boolean;
    showRequiredIndicator?: boolean;
    maxLength?: number;
    showCharacterCount?: boolean;
}

export const AccessibleTextarea: React.FC<AccessibleTextareaProps> = ({
    label,
    error,
    helpText,
    required = false,
    showRequiredIndicator = true,
    maxLength,
    showCharacterCount = false,
    className = '',
    value,
    ...textareaProps
}) => {
    const { generateId, getAriaProps } = useAriaAttributes();
    const { t } = useTranslation();

    const textareaId = React.useMemo(() => generateId('textarea'), [generateId]);
    const errorId = React.useMemo(() => generateId('error'), [generateId]);
    const helpId = React.useMemo(() => generateId('help'), [generateId]);
    const countId = React.useMemo(() => generateId('count'), [generateId]);

    const currentLength = typeof value === 'string' ? value.length : 0;
    const remainingChars = maxLength ? maxLength - currentLength : null;

    const describedBy = [
        error ? errorId : null,
        helpText ? helpId : null,
        showCharacterCount && maxLength ? countId : null,
    ].filter(Boolean).join(' ');

    return (
        <div className="space-y-2">
            <label
                htmlFor={textareaId}
                className="block text-sm font-medium text-gray-700 dark:text-gray-300"
            >
                {label}
                {required && showRequiredIndicator && (
                    <span className="text-red-500 ml-1" aria-label={t('accessibility.required_field')}>
                        *
                    </span>
                )}
            </label>

            <textarea
                id={textareaId}
                maxLength={maxLength}
                className={`
          block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 
          rounded-md shadow-sm placeholder-gray-400 dark:placeholder-gray-500
          focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500
          dark:bg-gray-700 dark:text-white resize-vertical
          ${error ? 'border-red-300 focus:ring-red-500 focus:border-red-500' : ''}
          ${className}
        `}
                value={value}
                {...getAriaProps({
                    required,
                    invalid: !!error,
                    describedBy: describedBy || undefined,
                })}
                {...textareaProps}
            />

            {showCharacterCount && maxLength && (
                <p
                    id={countId}
                    className={`text-sm ${remainingChars !== null && remainingChars < 20
                            ? 'text-red-600 dark:text-red-400'
                            : 'text-gray-500 dark:text-gray-400'
                        }`}
                    aria-live="polite"
                >
                    {remainingChars !== null && remainingChars >= 0
                        ? `${remainingChars} characters remaining`
                        : `${currentLength}/${maxLength} characters`}
                </p>
            )}

            {helpText && (
                <p id={helpId} className="text-sm text-gray-500 dark:text-gray-400">
                    {helpText}
                </p>
            )}

            {error && (
                <p
                    id={errorId}
                    className="text-sm text-red-600 dark:text-red-400"
                    role="alert"
                    aria-live="polite"
                >
                    {error}
                </p>
            )}
        </div>
    );
};

interface AccessibleCheckboxProps extends Omit<React.InputHTMLAttributes<HTMLInputElement>, 'id' | 'type'> {
    label: string;
    description?: string;
    error?: string;
    required?: boolean;
}

export const AccessibleCheckbox: React.FC<AccessibleCheckboxProps> = ({
    label,
    description,
    error,
    required = false,
    className = '',
    ...inputProps
}) => {
    const { generateId, getAriaProps } = useAriaAttributes();

    const checkboxId = React.useMemo(() => generateId('checkbox'), [generateId]);
    const errorId = React.useMemo(() => generateId('error'), [generateId]);
    const descriptionId = React.useMemo(() => generateId('description'), [generateId]);

    const describedBy = [
        error ? errorId : null,
        description ? descriptionId : null,
    ].filter(Boolean).join(' ');

    return (
        <div className="space-y-2">
            <div className="flex items-start">
                <input
                    id={checkboxId}
                    type="checkbox"
                    className={`
            h-4 w-4 text-blue-600 border-gray-300 dark:border-gray-600 
            rounded focus:ring-2 focus:ring-blue-500 dark:bg-gray-700
            ${error ? 'border-red-300 focus:ring-red-500' : ''}
            ${className}
          `}
                    {...getAriaProps({
                        required,
                        invalid: !!error,
                        describedBy: describedBy || undefined,
                    })}
                    {...inputProps}
                />
                <div className="ml-3">
                    <label
                        htmlFor={checkboxId}
                        className="text-sm font-medium text-gray-700 dark:text-gray-300"
                    >
                        {label}
                    </label>
                    {description && (
                        <p id={descriptionId} className="text-sm text-gray-500 dark:text-gray-400">
                            {description}
                        </p>
                    )}
                </div>
            </div>

            {error && (
                <p
                    id={errorId}
                    className="text-sm text-red-600 dark:text-red-400"
                    role="alert"
                    aria-live="polite"
                >
                    {error}
                </p>
            )}
        </div>
    );
};

interface AccessibleRadioGroupProps {
    name: string;
    label: string;
    options: { value: string; label: string; description?: string; disabled?: boolean }[];
    value?: string;
    onChange?: (value: string) => void;
    error?: string;
    required?: boolean;
    orientation?: 'horizontal' | 'vertical';
}

export const AccessibleRadioGroup: React.FC<AccessibleRadioGroupProps> = ({
    name,
    label,
    options,
    value,
    onChange,
    error,
    required = false,
    orientation = 'vertical',
}) => {
    const { generateId, getAriaProps } = useAriaAttributes();

    const groupId = React.useMemo(() => generateId('radio-group'), [generateId]);
    const errorId = React.useMemo(() => generateId('error'), [generateId]);

    return (
        <fieldset
            {...getAriaProps({
                invalid: !!error,
                describedBy: error ? errorId : undefined,
            })}
        >
            <legend className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">
                {label}
                {required && (
                    <span className="text-red-500 ml-1" aria-label="Required field">
                        *
                    </span>
                )}
            </legend>

            <div
                className={`space-${orientation === 'horizontal' ? 'x' : 'y'}-4 ${orientation === 'horizontal' ? 'flex flex-wrap' : ''
                    }`}
                role="radiogroup"
                aria-labelledby={groupId}
            >
                {options.map((option, index) => {
                    const radioId = `${name}-${option.value}`;
                    const descriptionId = option.description ? `${radioId}-description` : undefined;

                    return (
                        <div key={option.value} className="flex items-start">
                            <input
                                id={radioId}
                                name={name}
                                type="radio"
                                value={option.value}
                                checked={value === option.value}
                                onChange={(e) => onChange?.(e.target.value)}
                                disabled={option.disabled}
                                className="h-4 w-4 text-blue-600 border-gray-300 dark:border-gray-600 focus:ring-2 focus:ring-blue-500 dark:bg-gray-700"
                                {...getAriaProps({
                                    describedBy: descriptionId,
                                    posInSet: index + 1,
                                    setSize: options.length,
                                })}
                            />
                            <div className="ml-3">
                                <label
                                    htmlFor={radioId}
                                    className="text-sm font-medium text-gray-700 dark:text-gray-300"
                                >
                                    {option.label}
                                </label>
                                {option.description && (
                                    <p id={descriptionId} className="text-sm text-gray-500 dark:text-gray-400">
                                        {option.description}
                                    </p>
                                )}
                            </div>
                        </div>
                    );
                })}
            </div>

            {error && (
                <p
                    id={errorId}
                    className="mt-2 text-sm text-red-600 dark:text-red-400"
                    role="alert"
                    aria-live="polite"
                >
                    {error}
                </p>
            )}
        </fieldset>
    );
};