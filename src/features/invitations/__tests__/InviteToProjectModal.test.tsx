import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '../../../test/test-utils';
import { InviteToProjectModal } from '../InviteToProjectModal';

const mutate = vi.fn();

vi.mock('../api', () => ({
    useCreateInvitation: () => ({ mutate, isPending: false }),
}));

const onClose = vi.fn();

beforeEach(() => {
    mutate.mockReset();
    onClose.mockReset();
});

describe('InviteToProjectModal', () => {
    it('submits the email + selected role for this project', () => {
        render(<InviteToProjectModal isOpen onClose={onClose} projectId={3} projectName="mobile-app" />);

        fireEvent.change(screen.getByPlaceholderText('person@example.com'), { target: { value: 'carol@acme.io' } });
        fireEvent.click(screen.getByRole('button', { name: /send invite/i }));

        expect(mutate).toHaveBeenCalledTimes(1);
        expect(mutate.mock.calls[0][0]).toMatchObject({ email: 'carol@acme.io' });
    });

    it('blocks an invalid email and does not call the mutation', () => {
        render(<InviteToProjectModal isOpen onClose={onClose} projectId={3} projectName="mobile-app" />);

        const emailInput = screen.getByPlaceholderText('person@example.com');
        fireEvent.change(emailInput, { target: { value: 'not-an-email' } });
        // fireEvent.submit dispatches directly on the form, bypassing the browser's
        // own type="email" constraint validation that a real click on the submit
        // button would trigger first — this exercises the component's own regex
        // check instead.
        fireEvent.submit(emailInput.closest('form')!);

        expect(mutate).not.toHaveBeenCalled();
        expect(screen.getByText(/valid email/i)).toBeInTheDocument();
    });

    it('shows actionable copy when the domain allowlist rejects the invite', () => {
        mutate.mockImplementation((_vars, opts) =>
            opts.onError({ response: { data: { message: 'email domain is not on the allowlist' } } })
        );

        render(<InviteToProjectModal isOpen onClose={onClose} projectId={3} projectName="mobile-app" />);
        fireEvent.change(screen.getByPlaceholderText('person@example.com'), { target: { value: 'e@evil.example' } });
        fireEvent.click(screen.getByRole('button', { name: /send invite/i }));

        expect(screen.getByText(/contact a system admin to update the allowlist/i)).toBeInTheDocument();
    });
});
