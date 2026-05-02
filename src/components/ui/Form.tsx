import React from 'react';
import { useForm, UseFormReturn, FieldValues, SubmitHandler, UseFormProps } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { clsx } from 'clsx';

// Form context to pass form methods to child components
const FormContext = React.createContext<UseFormReturn<any> | null>(null);

export const useFormContext = <T extends FieldValues = FieldValues>(): UseFormReturn<T> => {
    const context = React.useContext(FormContext);
    if (!context) {
        throw new Error('useFormContext must be used within a Form component');
    }
    return context as UseFormReturn<T>;
};

export interface FormProps<T extends FieldValues = FieldValues> extends Omit<React.FormHTMLAttributes<HTMLFormElement>, 'onSubmit'> {
    schema?: z.ZodSchema<T>;
    onSubmit: SubmitHandler<T>;
    defaultValues?: UseFormProps<T>['defaultValues'];
    mode?: UseFormProps<T>['mode'];
    children: React.ReactNode;
    className?: string;
}

function Form<T extends FieldValues = FieldValues>({
    schema,
    onSubmit,
    defaultValues,
    mode = 'onChange',
    children,
    className,
    ...props
}: FormProps<T>) {
    const formMethods = useForm<T>({
        ...(schema && { resolver: zodResolver(schema) }),
        ...(defaultValues && { defaultValues }),
        mode,
    });

    const { handleSubmit } = formMethods;

    return (
        <FormContext.Provider value={formMethods}>
            <form
                onSubmit={handleSubmit(onSubmit as SubmitHandler<FieldValues>)}
                className={clsx('space-y-4', className)}
                {...props}
            >
                {children}
            </form>
        </FormContext.Provider>
    );
}

// Form field wrapper component
export interface FormFieldProps {
    name: string;
    children: (field: {
        value: any;
        onChange: (value: any) => void;
        onBlur: () => void;
        error?: string | undefined;
    }) => React.ReactNode;
}

const FormField: React.FC<FormFieldProps> = ({ name, children }) => {
    const { register, formState: { errors }, setValue, watch } = useFormContext();

    const error = errors[name]?.message as string | undefined;
    const value = watch(name);

    const { onChange, onBlur } = register(name);

    const handleChange = (newValue: any) => {
        setValue(name, newValue, { shouldValidate: true, shouldDirty: true });
        onChange({ target: { value: newValue, name } });
    };

    return (
        <>
            {children({
                value,
                onChange: handleChange,
                onBlur: () => onBlur({ target: { value, name } }),
                error,
            })}
        </>
    );
};

// Form section component for grouping related fields
export interface FormSectionProps {
    title?: string;
    description?: string;
    children: React.ReactNode;
    className?: string;
}

const FormSection: React.FC<FormSectionProps> = ({
    title,
    description,
    children,
    className,
}) => {
    return (
        <div className={clsx('space-y-4', className)}>
            {(title || description) && (
                <div className="border-b border-gray-200 pb-4">
                    {title && (
                        <h3 className="text-lg font-medium text-gray-900">
                            {title}
                        </h3>
                    )}
                    {description && (
                        <p className="mt-1 text-sm text-gray-500">
                            {description}
                        </p>
                    )}
                </div>
            )}
            <div className="space-y-4">
                {children}
            </div>
        </div>
    );
};

// Form actions component for submit/cancel buttons
export interface FormActionsProps {
    children: React.ReactNode;
    align?: 'left' | 'right' | 'center';
    className?: string;
}

const FormActions: React.FC<FormActionsProps> = ({
    children,
    align = 'right',
    className,
}) => {
    const alignmentClasses = {
        left: 'justify-start',
        right: 'justify-end',
        center: 'justify-center',
    };

    return (
        <div className={clsx(
            'flex space-x-3 pt-4 border-t border-gray-200',
            alignmentClasses[align],
            className
        )}>
            {children}
        </div>
    );
};

export { Form, FormField, FormSection, FormActions };