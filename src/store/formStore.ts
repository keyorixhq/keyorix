import React from 'react';
import { create } from 'zustand';
import { devtools } from 'zustand/middleware';

interface FormField {
    value: any;
    error?: string | undefined;
    touched: boolean;
    dirty: boolean;
    validating?: boolean;
    disabled?: boolean;
}

interface FormMetadata {
    submitting: boolean;
    submitCount: number;
    lastSubmitTime: string | null;
    autoSave: boolean;
    autoSaveInterval: number;
    initialValues: Record<string, any>;
    validationSchema?: any;
}

interface FormState {
    forms: Record<string, Record<string, FormField>>;
    formMeta: Record<string, FormMetadata>;

    // Form management
    initializeForm: (formId: string, initialValues: Record<string, any>, meta?: Partial<FormMetadata>) => void;
    destroyForm: (formId: string) => void;
    resetForm: (formId: string, values?: Record<string, any>) => void;

    // Field management
    setFieldValue: (formId: string, fieldName: string, value: any) => void;
    setFieldError: (formId: string, fieldName: string, error?: string) => void;
    setFieldTouched: (formId: string, fieldName: string, touched?: boolean) => void;
    setFieldValidating: (formId: string, fieldName: string, validating?: boolean) => void;
    setFieldDisabled: (formId: string, fieldName: string, disabled?: boolean) => void;
    touchAllFields: (formId: string) => void;

    // Bulk operations
    setFormValues: (formId: string, values: Record<string, any>) => void;
    setFormErrors: (formId: string, errors: Record<string, string>) => void;
    setFormSubmitting: (formId: string, submitting: boolean) => void;
    setFormAutoSave: (formId: string, enabled: boolean) => void;

    // Getters
    getFormValues: (formId: string) => Record<string, any>;
    getFormErrors: (formId: string) => Record<string, string>;
    getFormMeta: (formId: string) => FormMetadata | undefined;
    isFormValid: (formId: string) => boolean;
    isFormDirty: (formId: string) => boolean;
    isFormTouched: (formId: string) => boolean;
    isFormSubmitting: (formId: string) => boolean;
    hasFormChanged: (formId: string) => boolean;

    // Auto-save functionality
    saveFormDraft: (formId: string) => void;
    loadFormDraft: (formId: string) => void;
    clearFormDraft: (formId: string) => void;
}

export const useFormStore = create<FormState>()(
    devtools(
        (set, get) => ({
            forms: {},
            formMeta: {},

            initializeForm: (formId, initialValues, meta = {}) => {
                const fields: Record<string, FormField> = {};

                Object.keys(initialValues).forEach(key => {
                    fields[key] = {
                        value: initialValues[key],
                        touched: false,
                        dirty: false,
                        validating: false,
                        disabled: false,
                    };
                });

                const formMetadata: FormMetadata = {
                    submitting: false,
                    submitCount: 0,
                    lastSubmitTime: null,
                    autoSave: false,
                    autoSaveInterval: 30000, // 30 seconds
                    initialValues: { ...initialValues },
                    ...meta,
                };

                set((state) => ({
                    forms: {
                        ...state.forms,
                        [formId]: fields,
                    },
                    formMeta: {
                        ...state.formMeta,
                        [formId]: formMetadata,
                    },
                }));
            },

            destroyForm: (formId) => {
                set((state) => {
                    const { [formId]: removedForm, ...restForms } = state.forms;
                    const { [formId]: removedMeta, ...restMeta } = state.formMeta;
                    return {
                        forms: restForms,
                        formMeta: restMeta,
                    };
                });

                // Clear any saved draft
                get().clearFormDraft(formId);
            },

            resetForm: (formId, values) => {
                const form = get().forms[formId];
                const meta = get().formMeta[formId];
                if (!form || !meta) return;

                const resetValues = values || meta.initialValues;
                const fields: Record<string, FormField> = {};

                Object.keys(form).forEach(key => {
                    const field = form[key];
                    if (field) {
                        fields[key] = {
                            value: resetValues[key] !== undefined ? resetValues[key] : field.value,
                            touched: false,
                            dirty: false,
                            error: undefined,
                            validating: false,
                            disabled: false,
                        };
                    }
                });

                set((state) => ({
                    forms: {
                        ...state.forms,
                        [formId]: fields,
                    },
                }));
            },

            setFieldValue: (formId, fieldName, value) => {
                set((state) => {
                    const form = state.forms[formId];
                    if (!form || !form[fieldName]) return state;

                    return {
                        forms: {
                            ...state.forms,
                            [formId]: {
                                ...form,
                                [fieldName]: {
                                    ...form[fieldName],
                                    value,
                                    dirty: true,
                                },
                            },
                        },
                    };
                });
            },

            setFieldError: (formId, fieldName, error) => {
                set((state) => {
                    const form = state.forms[formId];
                    if (!form || !form[fieldName]) return state;

                    return {
                        forms: {
                            ...state.forms,
                            [formId]: {
                                ...form,
                                [fieldName]: {
                                    ...form[fieldName],
                                    error,
                                },
                            },
                        },
                    };
                });
            },

            setFieldTouched: (formId, fieldName, touched = true) => {
                set((state) => {
                    const form = state.forms[formId];
                    if (!form || !form[fieldName]) return state;

                    return {
                        forms: {
                            ...state.forms,
                            [formId]: {
                                ...form,
                                [fieldName]: {
                                    ...form[fieldName],
                                    touched,
                                },
                            },
                        },
                    };
                });
            },

            setFieldValidating: (formId, fieldName, validating = true) => {
                set((state) => {
                    const form = state.forms[formId];
                    if (!form || !form[fieldName]) return state;

                    return {
                        forms: {
                            ...state.forms,
                            [formId]: {
                                ...form,
                                [fieldName]: {
                                    ...form[fieldName],
                                    validating,
                                },
                            },
                        },
                    };
                });
            },

            setFieldDisabled: (formId, fieldName, disabled = true) => {
                set((state) => {
                    const form = state.forms[formId];
                    if (!form || !form[fieldName]) return state;

                    return {
                        forms: {
                            ...state.forms,
                            [formId]: {
                                ...form,
                                [fieldName]: {
                                    ...form[fieldName],
                                    disabled,
                                },
                            },
                        },
                    };
                });
            },

            touchAllFields: (formId) => {
                set((state) => {
                    const form = state.forms[formId];
                    if (!form) return state;

                    const touchedForm: Record<string, FormField> = {};
                    Object.keys(form).forEach(key => {
                        const field = form[key];
                        if (field) {
                            touchedForm[key] = {
                                ...field,
                                touched: true,
                            };
                        }
                    });

                    return {
                        forms: {
                            ...state.forms,
                            [formId]: touchedForm,
                        },
                    };
                });
            },

            setFormValues: (formId, values) => {
                set((state) => {
                    const form = state.forms[formId];
                    if (!form) return state;

                    const updatedForm: Record<string, FormField> = { ...form };
                    Object.keys(values).forEach(key => {
                        if (updatedForm[key]) {
                            updatedForm[key] = {
                                ...updatedForm[key],
                                value: values[key],
                                dirty: true,
                            };
                        }
                    });

                    return {
                        forms: {
                            ...state.forms,
                            [formId]: updatedForm,
                        },
                    };
                });
            },

            setFormErrors: (formId, errors) => {
                set((state) => {
                    const form = state.forms[formId];
                    if (!form) return state;

                    const updatedForm: Record<string, FormField> = { ...form };
                    Object.keys(errors).forEach(key => {
                        const field = updatedForm[key];
                        if (field) {
                            updatedForm[key] = {
                                ...field,
                                error: errors[key],
                            };
                        }
                    });

                    return {
                        forms: {
                            ...state.forms,
                            [formId]: updatedForm,
                        },
                    };
                });
            },

            setFormSubmitting: (formId, submitting) => {
                set((state) => {
                    const meta = state.formMeta[formId];
                    if (!meta) return state;

                    const updatedMeta: FormMetadata = {
                        ...meta,
                        submitting,
                        ...(submitting ? {} : {
                            submitCount: meta.submitCount + 1,
                            lastSubmitTime: new Date().toISOString(),
                        }),
                    };

                    return {
                        formMeta: {
                            ...state.formMeta,
                            [formId]: updatedMeta,
                        },
                    };
                });
            },

            setFormAutoSave: (formId, enabled) => {
                set((state) => {
                    const meta = state.formMeta[formId];
                    if (!meta) return state;

                    const updatedMeta: FormMetadata = {
                        ...meta,
                        autoSave: enabled,
                    };

                    return {
                        formMeta: {
                            ...state.formMeta,
                            [formId]: updatedMeta,
                        },
                    };
                });
            },

            getFormValues: (formId) => {
                const form = get().forms[formId];
                if (!form) return {};

                const values: Record<string, any> = {};
                Object.keys(form).forEach(key => {
                    const field = form[key];
                    if (field) {
                        values[key] = field.value;
                    }
                });
                return values;
            },

            getFormErrors: (formId) => {
                const form = get().forms[formId];
                if (!form) return {};

                const errors: Record<string, string> = {};
                Object.keys(form).forEach(key => {
                    const field = form[key];
                    if (field?.error) {
                        errors[key] = field.error;
                    }
                });
                return errors;
            },

            getFormMeta: (formId) => {
                return get().formMeta[formId];
            },

            isFormValid: (formId) => {
                const form = get().forms[formId];
                if (!form) return true;

                return Object.values(form).every(field => !field.error);
            },

            isFormDirty: (formId) => {
                const form = get().forms[formId];
                if (!form) return false;

                return Object.values(form).some(field => field.dirty);
            },

            isFormTouched: (formId) => {
                const form = get().forms[formId];
                if (!form) return false;

                return Object.values(form).some(field => field.touched);
            },

            isFormSubmitting: (formId) => {
                const meta = get().formMeta[formId];
                return meta?.submitting ?? false;
            },

            hasFormChanged: (formId) => {
                const form = get().forms[formId];
                const meta = get().formMeta[formId];
                if (!form || !meta) return false;

                const currentValues = get().getFormValues(formId);
                const initialValues = meta.initialValues;

                return JSON.stringify(currentValues) !== JSON.stringify(initialValues);
            },

            saveFormDraft: (formId) => {
                const values = get().getFormValues(formId);
                const key = `form_draft_${formId}`;

                try {
                    localStorage.setItem(key, JSON.stringify({
                        values,
                        timestamp: new Date().toISOString(),
                    }));
                } catch (error) {
                    console.warn('Failed to save form draft:', error);
                }
            },

            loadFormDraft: (formId) => {
                const key = `form_draft_${formId}`;

                try {
                    const draft = localStorage.getItem(key);
                    if (draft) {
                        const { values, timestamp } = JSON.parse(draft);

                        // Check if draft is not too old (24 hours)
                        const draftAge = Date.now() - new Date(timestamp).getTime();
                        const maxAge = 24 * 60 * 60 * 1000; // 24 hours

                        if (draftAge < maxAge) {
                            get().setFormValues(formId, values);
                            return true;
                        } else {
                            // Remove old draft
                            localStorage.removeItem(key);
                        }
                    }
                } catch (error) {
                    console.warn('Failed to load form draft:', error);
                }

                return false;
            },

            clearFormDraft: (formId) => {
                const key = `form_draft_${formId}`;
                try {
                    localStorage.removeItem(key);
                } catch (error) {
                    console.warn('Failed to clear form draft:', error);
                }
            },
        }),
        {
            name: 'form-store',
        }
    )
);

// Custom hook for form field management
export const useFormField = (formId: string, fieldName: string) => {
    const {
        forms,
        setFieldValue,
        setFieldError,
        setFieldTouched,
        setFieldValidating,
        setFieldDisabled,
    } = useFormStore();

    const field = forms[formId]?.[fieldName];

    return {
        value: field?.value,
        error: field?.error,
        touched: field?.touched,
        dirty: field?.dirty,
        validating: field?.validating,
        disabled: field?.disabled,
        setValue: (value: any) => setFieldValue(formId, fieldName, value),
        setError: (error?: string) => setFieldError(formId, fieldName, error),
        setTouched: (touched = true) => setFieldTouched(formId, fieldName, touched),
        setValidating: (validating = true) => setFieldValidating(formId, fieldName, validating),
        setDisabled: (disabled = true) => setFieldDisabled(formId, fieldName, disabled),
    };
};

// Custom hook for entire form management
export const useForm = (formId: string) => {
    const {
        initializeForm,
        destroyForm,
        resetForm,
        setFormValues,
        setFormErrors,
        setFormSubmitting,
        setFormAutoSave,
        touchAllFields,
        getFormValues,
        getFormErrors,
        getFormMeta,
        isFormValid,
        isFormDirty,
        isFormTouched,
        isFormSubmitting,
        hasFormChanged,
        saveFormDraft,
        loadFormDraft,
        clearFormDraft,
    } = useFormStore();

    return {
        initialize: (initialValues: Record<string, any>, meta?: Partial<FormMetadata>) =>
            initializeForm(formId, initialValues, meta),
        destroy: () => destroyForm(formId),
        reset: (values?: Record<string, any>) => resetForm(formId, values),
        setValues: (values: Record<string, any>) => setFormValues(formId, values),
        setErrors: (errors: Record<string, string>) => setFormErrors(formId, errors),
        initialize: (initialValues: Record<string, any>, meta?: Partial<FormMetadata>) =>
            initializeForm(formId, initialValues, meta),
        destroy: () => destroyForm(formId),
        reset: (values?: Record<string, any>) => resetForm(formId, values),
        setValues: (values: Record<string, any>) => setFormValues(formId, values),
        setErrors: (errors: Record<string, string>) => setFormErrors(formId, errors),
        setSubmitting: (submitting: boolean) => setFormSubmitting(formId, submitting),
        setAutoSave: (enabled: boolean) => setFormAutoSave(formId, enabled),
        touchAll: () => touchAllFields(formId),
        getValues: () => getFormValues(formId),
        getErrors: () => getFormErrors(formId),
        getMeta: () => getFormMeta(formId),
        isValid: () => isFormValid(formId),
        isDirty: () => isFormDirty(formId),
        isTouched: () => isFormTouched(formId),
        isSubmitting: () => isFormSubmitting(formId),
        hasChanged: () => hasFormChanged(formId),
        saveDraft: () => saveFormDraft(formId),
        loadDraft: () => loadFormDraft(formId),
        clearDraft: () => clearFormDraft(formId),
    };
};

// Custom hook for auto-save functionality
export const useFormAutoSave = (formId: string, onSave?: (values: Record<string, any>) => Promise<void>) => {
    const { getFormMeta, getFormValues, hasFormChanged, saveFormDraft } = useFormStore();

    React.useEffect(() => {
        const meta = getFormMeta(formId);
        if (!meta?.autoSave) return;

        const interval = setInterval(() => {
            if (hasFormChanged(formId)) {
                const values = getFormValues(formId);

                // Save draft to localStorage
                saveFormDraft(formId);

                // Call custom save function if provided
                if (onSave) {
                    onSave(values).catch(error => {
                        console.warn('Auto-save failed:', error);
                    });
                }
            }
        }, meta.autoSaveInterval);

        return () => clearInterval(interval);
    }, [formId, onSave, getFormMeta, getFormValues, hasFormChanged, saveFormDraft]);
};