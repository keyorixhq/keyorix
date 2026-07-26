import * as React from 'react';
import {
    Controller,
    FormProvider,
    useFormContext,
    type ControllerProps,
    type FieldPath,
    type FieldValues,
} from 'react-hook-form';
import { cn } from '@/lib/utils';

// ── Form ──────────────────────────────────────────────────────────────────────
// Thin alias for FormProvider — callers own the useForm() call:
//   const form = useForm({ resolver: zodResolver(schema) });
//   <Form {...form}><form onSubmit={form.handleSubmit(onSubmit)}>…</form></Form>

const Form = FormProvider;

// ── FormField ─────────────────────────────────────────────────────────────────
// Controller wrapper that puts the field name in context for child components.

type FormFieldContextValue<
    TFieldValues extends FieldValues = FieldValues,
    TName extends FieldPath<TFieldValues> = FieldPath<TFieldValues>,
> = { name: TName };

const FormFieldContext = React.createContext<FormFieldContextValue>({} as FormFieldContextValue);

function FormField<
    TFieldValues extends FieldValues = FieldValues,
    TName extends FieldPath<TFieldValues> = FieldPath<TFieldValues>,
>(props: ControllerProps<TFieldValues, TName>) {
    return (
        <FormFieldContext.Provider value={{ name: props.name }}>
            <Controller {...props} />
        </FormFieldContext.Provider>
    );
}

// ── useFormField ──────────────────────────────────────────────────────────────

type FormItemContextValue = { id: string };
const FormItemContext = React.createContext<FormItemContextValue>({} as FormItemContextValue);

export function useFormField() {
    const fieldCtx = React.useContext(FormFieldContext);
    const itemCtx = React.useContext(FormItemContext);
    const { getFieldState, formState } = useFormContext();
    const fieldState = getFieldState(fieldCtx.name, formState);

    if (!fieldCtx.name) throw new Error('useFormField must be used within <FormField>');

    const { id } = itemCtx;
    return {
        id,
        name: fieldCtx.name,
        formItemId: `${id}-item`,
        formDescriptionId: `${id}-desc`,
        formMessageId: `${id}-msg`,
        ...fieldState,
    };
}

// ── FormItem ──────────────────────────────────────────────────────────────────

const FormItem = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(
    ({ className, ...props }, ref) => {
        const id = React.useId();
        return (
            <FormItemContext.Provider value={{ id }}>
                <div ref={ref} className={cn('space-y-1.5', className)} {...props} />
            </FormItemContext.Provider>
        );
    }
);
FormItem.displayName = 'FormItem';

// ── FormLabel ─────────────────────────────────────────────────────────────────

const FormLabel = React.forwardRef<HTMLLabelElement, React.LabelHTMLAttributes<HTMLLabelElement>>(
    ({ className, ...props }, ref) => {
        const { error, formItemId } = useFormField();
        return (
            <label
                ref={ref}
                htmlFor={formItemId}
                className={cn(
                    'block text-sm font-medium',
                    error ? 'text-[var(--error)]' : 'text-base-secondary',
                    className
                )}
                {...props}
            />
        );
    }
);
FormLabel.displayName = 'FormLabel';

// ── FormControl ───────────────────────────────────────────────────────────────
// Wraps the control with the correct id and aria attrs for the field.

const FormControl = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement>>(({ ...props }, ref) => {
    const { error, formItemId, formDescriptionId, formMessageId } = useFormField();
    return (
        <div
            ref={ref}
            id={formItemId}
            aria-describedby={error ? `${formDescriptionId} ${formMessageId}` : formDescriptionId}
            aria-invalid={!!error}
            {...props}
        />
    );
});
FormControl.displayName = 'FormControl';

// ── FormDescription ───────────────────────────────────────────────────────────

const FormDescription = React.forwardRef<HTMLParagraphElement, React.HTMLAttributes<HTMLParagraphElement>>(
    ({ className, ...props }, ref) => {
        const { formDescriptionId } = useFormField();
        return <p ref={ref} id={formDescriptionId} className={cn('text-sm text-base-muted', className)} {...props} />;
    }
);
FormDescription.displayName = 'FormDescription';

// ── FormMessage ───────────────────────────────────────────────────────────────

const FormMessage = React.forwardRef<HTMLParagraphElement, React.HTMLAttributes<HTMLParagraphElement>>(
    ({ className, children, ...props }, ref) => {
        const { error, formMessageId } = useFormField();
        const body = error ? String(error.message ?? '') : children;
        if (!body) return null;
        return (
            <p
                ref={ref}
                id={formMessageId}
                role="alert"
                className={cn('text-sm text-[var(--error)]', className)}
                {...props}
            >
                {body}
            </p>
        );
    }
);
FormMessage.displayName = 'FormMessage';

export { Form, FormField, FormItem, FormLabel, FormControl, FormDescription, FormMessage };
