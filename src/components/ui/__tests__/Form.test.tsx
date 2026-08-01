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

        // FormControl renders its own wrapping <div> (id/aria live on the div,
        // not forwarded onto the child control) — see the documented bug test below.
        const controlWrapper = input.parentElement as HTMLElement;

        expect(controlWrapper).not.toBeNull();
        expect(controlWrapper.tagName).toBe('DIV');
        expect(label).toHaveAttribute('for', controlWrapper.id);
        expect(controlWrapper).toHaveAttribute('aria-invalid', 'false');
        expect(controlWrapper.getAttribute('aria-describedby')).toBe(description.id);
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
        const controlWrapper = input.parentElement as HTMLElement;
        const description = screen.getByText('Pick a unique username');

        expect(controlWrapper).toHaveAttribute('aria-invalid', 'true');
        expect(controlWrapper.getAttribute('aria-describedby')).toBe(`${description.id} ${alert.id}`);

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

        const usernameWrapper = screen.getByTestId('username-input').parentElement as HTMLElement;
        const emailWrapper = screen.getByTestId('email-input').parentElement as HTMLElement;

        expect(usernameWrapper.id).not.toBe(emailWrapper.id);
        expect(screen.getByText('Username')).toHaveAttribute('for', usernameWrapper.id);
        expect(screen.getByText('Email')).toHaveAttribute('for', emailWrapper.id);
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

    // Documented, not fixed (coverage-only PR — see house rules): FormControl
    // renders its own wrapping <div id={formItemId} aria-*> around whatever
    // control is passed as children, instead of forwarding those attributes
    // onto the child itself (e.g. via a Radix Slot, as shadcn/ui's original
    // does). FormLabel's `htmlFor` therefore points at that wrapping <div>,
    // not at the actual <input> — so there is no native label/control
    // association, and `getByLabelText` cannot find the input by its label.
    it('documents a bug: the label/control id lands on FormControl wrapping div, not the input itself', () => {
        render(<UsernameForm />);

        expect(screen.queryByLabelText('Username')).not.toBeInTheDocument();
        expect(screen.getByTestId('username-input')).not.toHaveAttribute('id');
    });
});
