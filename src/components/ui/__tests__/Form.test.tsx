import * as React from 'react';
import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { useForm, FormProvider } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { Form, FormField, FormItem, FormLabel, FormControl, FormDescription, FormMessage } from '../Form';

const schema = z.object({
    username: z.string().min(3, 'Username must be at least 3 characters'),
});

type FormValues = z.infer<typeof schema>;

function UsernameForm({
    onSubmit = vi.fn(),
    defaultValues = { username: '' },
    withDescription = true,
    messageChildren,
}: {
    onSubmit?: (data: FormValues) => void;
    defaultValues?: FormValues;
    withDescription?: boolean;
    messageChildren?: React.ReactNode;
}) {
    const form = useForm<FormValues>({
        resolver: zodResolver(schema),
        defaultValues,
    });

    return (
        <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} noValidate>
                <FormField
                    control={form.control}
                    name="username"
                    render={({ field }) => (
                        <FormItem>
                            <FormLabel>Username</FormLabel>
                            <FormControl>
                                <input {...field} data-testid="username-input" />
                            </FormControl>
                            {withDescription && <FormDescription>Pick a unique username</FormDescription>}
                            <FormMessage>{messageChildren}</FormMessage>
                        </FormItem>
                    )}
                />
                <button type="submit">Submit</button>
            </form>
        </Form>
    );
}

const twoFieldSchema = z.object({
    username: z.string().min(1, 'Username is required'),
    email: z.string().min(1, 'Email is required'),
});
type TwoFieldValues = z.infer<typeof twoFieldSchema>;

function TwoFieldForm() {
    const form = useForm<TwoFieldValues>({
        resolver: zodResolver(twoFieldSchema),
        defaultValues: { username: '', email: '' },
    });

    return (
        <Form {...form}>
            <form>
                <FormField
                    control={form.control}
                    name="username"
                    render={({ field }) => (
                        <FormItem>
                            <FormLabel>Username</FormLabel>
                            <FormControl>
                                <input {...field} data-testid="username-input" />
                            </FormControl>
                        </FormItem>
                    )}
                />
                <FormField
                    control={form.control}
                    name="email"
                    render={({ field }) => (
                        <FormItem>
                            <FormLabel>Email</FormLabel>
                            <FormControl>
                                <input {...field} data-testid="email-input" />
                            </FormControl>
                        </FormItem>
                    )}
                />
            </form>
        </Form>
    );
}

describe('Form', () => {
    afterEach(() => {
        vi.restoreAllMocks();
    });

    it('is a plain alias for react-hook-form FormProvider', () => {
        expect(Form).toBe(FormProvider);
    });

    it('wires label, control, and description together when the field is valid', () => {
        render(<UsernameForm />);

        const label = screen.getByText('Username');
        const input = screen.getByTestId('username-input');
        const description = screen.getByText('Pick a unique username');

        // FormControl merges id/aria attrs onto the real control via Slot,
        // instead of wrapping it in a <div> — see the label-association test below.
        expect(input.tagName).toBe('INPUT');
        expect(label).toHaveAttribute('for', input.id);
        expect(input).toHaveAttribute('aria-invalid', 'false');
        expect(input.getAttribute('aria-describedby')).toBe(description.id);
        expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    });

    it('does not render FormMessage when there is no error and no children', () => {
        render(<UsernameForm />);
        expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    });

    it('renders static FormMessage children when there is no error', () => {
        render(<UsernameForm messageChildren="Helper message" />);
        const message = screen.getByText('Helper message');
        expect(message).toHaveAttribute('role', 'alert');
    });

    it('shows the validation error, flips aria-invalid, and expands aria-describedby after a failed submit', async () => {
        const onSubmit = vi.fn();
        render(<UsernameForm onSubmit={onSubmit} />);

        fireEvent.click(screen.getByText('Submit'));

        const alert = await screen.findByRole('alert');
        expect(alert).toHaveTextContent('Username must be at least 3 characters');
        expect(onSubmit).not.toHaveBeenCalled();

        const input = screen.getByTestId('username-input');
        const description = screen.getByText('Pick a unique username');

        expect(input).toHaveAttribute('aria-invalid', 'true');
        expect(input.getAttribute('aria-describedby')).toBe(`${description.id} ${alert.id}`);

        const label = screen.getByText('Username');
        expect(label.className).toContain('text-[var(--error)]');
    });

    it('prefers the RHF error message over static children when both are present', async () => {
        render(<UsernameForm messageChildren="Helper message" />);

        fireEvent.click(screen.getByText('Submit'));

        const alert = await screen.findByRole('alert');
        expect(alert).toHaveTextContent('Username must be at least 3 characters');
        expect(screen.queryByText('Helper message')).not.toBeInTheDocument();
    });

    it('submits successfully once the field passes validation', async () => {
        const onSubmit = vi.fn();
        render(<UsernameForm onSubmit={onSubmit} />);

        fireEvent.change(screen.getByTestId('username-input'), { target: { value: 'validname' } });
        fireEvent.click(screen.getByText('Submit'));

        await waitFor(() => expect(onSubmit).toHaveBeenCalledTimes(1));
        expect(onSubmit).toHaveBeenCalledWith({ username: 'validname' }, expect.anything());
        expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    });

    it('gives each FormItem instance a unique id so sibling fields do not collide', () => {
        render(<TwoFieldForm />);

        const usernameInput = screen.getByTestId('username-input');
        const emailInput = screen.getByTestId('email-input');

        expect(usernameInput.id).not.toBe(emailInput.id);
        expect(screen.getByText('Username')).toHaveAttribute('for', usernameInput.id);
        expect(screen.getByText('Email')).toHaveAttribute('for', emailInput.id);
    });

    it('throws when a form-field-aware component is rendered outside of FormField', () => {
        const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

        function BadLabel() {
            const form = useForm({ defaultValues: { username: '' } });
            return (
                <Form {...form}>
                    <FormLabel>Oops</FormLabel>
                </Form>
            );
        }

        expect(() => render(<BadLabel />)).toThrow('useFormField must be used within <FormField>');
        consoleErrorSpy.mockRestore();
    });

    // FormControl merges id/aria-* onto the actual control element via Radix's
    // Slot, instead of wrapping it in its own <div>. FormLabel's `htmlFor`
    // therefore resolves to the real, focusable <input> — giving a native
    // label/control association that `getByLabelText` can traverse.
    it('associates the label with the real control element via Slot, not a wrapping div', () => {
        render(<UsernameForm />);

        const input = screen.getByLabelText('Username');
        expect(input).toBe(screen.getByTestId('username-input'));
        expect(input.tagName).toBe('INPUT');
        expect(input).toHaveAttribute('id');
    });

    // Covers the `error.message ?? ''` fallback: a manually-set error with no
    // message resolves to an empty body, so FormMessage renders nothing at all
    // (the `!body` early-return), distinct from the "no error" case above which
    // is reached through a different branch (`children` being undefined).
    it('renders nothing when the field error has no message', () => {
        function ErrorNoMessageForm() {
            const form = useForm<{ username: string }>({ defaultValues: { username: '' } });
            React.useEffect(() => {
                form.setError('username', { type: 'manual' });
            }, [form]);

            return (
                <Form {...form}>
                    <FormField
                        control={form.control}
                        name="username"
                        render={() => (
                            <FormItem>
                                <FormMessage />
                            </FormItem>
                        )}
                    />
                </Form>
            );
        }

        render(<ErrorNoMessageForm />);
        expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    });
});
