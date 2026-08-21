import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '../../../test/test-utils';
import { InviteToProjectModal } from '../InviteToProjectModal';

const mutate = vi.fn();
let isPending = false;

vi.mock('../api', () => ({
    useCreateInvitation: () => ({ mutate, isPending }),
}));

const onClose = vi.fn();

beforeEach(() => {
    mutate.mockReset();
    onClose.mockReset();
    isPending = false;
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

    it('resets fields and calls onClose on Cancel (not pending)', () => {
        const { rerender } = render(
            <InviteToProjectModal isOpen onClose={onClose} projectId={3} projectName="mobile-app" />
        );

        fireEvent.change(screen.getByPlaceholderText('person@example.com'), { target: { value: 'temp@x.io' } });
        fireEvent.click(screen.getByRole('button', { name: /cancel/i }));

        expect(onClose).toHaveBeenCalledTimes(1);

        // The component instance persists across isOpen toggles — reopening shows
        // the state was actually reset.
        rerender(<InviteToProjectModal isOpen onClose={onClose} projectId={3} projectName="mobile-app" />);
        expect(screen.getByPlaceholderText('person@example.com')).toHaveValue('');
    });

    it('Cancel is a no-op while sending, and the button shows "Sending…"', () => {
        isPending = true;
        render(<InviteToProjectModal isOpen onClose={onClose} projectId={3} projectName="mobile-app" />);

        expect(screen.getByRole('button', { name: /sending…/i })).toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: /cancel/i }));

        expect(onClose).not.toHaveBeenCalled();
    });

    it("handleClose is also a no-op while pending via the modal's own close button", () => {
        // The Cancel button is `disabled` while pending, so clicking it never
        // actually reaches handleClose's body. Radix's dialog close ("X") button
        // isn't wired to isPending, so it's the only DOM path that exercises
        // handleClose's early-return guard during a pending mutation.
        isPending = true;
        render(<InviteToProjectModal isOpen onClose={onClose} projectId={3} projectName="mobile-app" />);

        fireEvent.click(screen.getByRole('button', { name: /close/i }));

        expect(onClose).not.toHaveBeenCalled();
    });

    it('resets fields and closes on a successful submission', () => {
        mutate.mockImplementation((_vars, opts) => opts.onSuccess());

        const { rerender } = render(
            <InviteToProjectModal isOpen onClose={onClose} projectId={3} projectName="mobile-app" />
        );
        fireEvent.change(screen.getByPlaceholderText('person@example.com'), { target: { value: 'carol@acme.io' } });
        fireEvent.click(screen.getByRole('button', { name: /send invite/i }));

        expect(onClose).toHaveBeenCalledTimes(1);
        rerender(<InviteToProjectModal isOpen onClose={onClose} projectId={3} projectName="mobile-app" />);
        expect(screen.getByPlaceholderText('person@example.com')).toHaveValue('');
    });

    it('submits the role chosen from the dropdown', () => {
        render(<InviteToProjectModal isOpen onClose={onClose} projectId={3} projectName="mobile-app" />);

        fireEvent.change(screen.getByPlaceholderText('person@example.com'), { target: { value: 'carol@acme.io' } });
        fireEvent.change(screen.getByRole('combobox'), { target: { value: 'project_admin' } });
        fireEvent.click(screen.getByRole('button', { name: /send invite/i }));

        expect(mutate.mock.calls[0][0]).toMatchObject({ role: 'project_admin' });
    });
});
