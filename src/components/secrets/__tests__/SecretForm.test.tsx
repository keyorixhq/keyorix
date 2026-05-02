import { render, screen, fireEvent, waitFor } from '../../test/test-utils';
import { SecretForm } from '../SecretForm';
import { createMockSecret } from '../../test/test-utils';

describe('SecretForm', () => {
    const mockOnSubmit = vi.fn();
    const mockOnCancel = vi.fn();

    beforeEach(() => {
        vi.clearAllMocks();
    });

    it('renders create form correctly', () => {
        render(
            <SecretForm
                mode="create"
                onSubmit={mockOnSubmit}
                onCancel={mockOnCancel}
            />
        );

        expect(screen.getByText('Create Secret')).toBeInTheDocument();
        expect(screen.getByLabelText('Name')).toBeInTheDocument();
        expect(screen.getByLabelText('Type')).toBeInTheDocument();
        expect(screen.getByLabelText('Value')).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Create Secret' })).toBeInTheDocument();
    });

    it('renders edit form with initial values', () => {
        const secret = createMockSecret({
            name: 'test-secret',
            type: 'password',
            value: 'secret-value',
        });

        render(
            <SecretForm
                mode="edit"
                initialData={secret}
                onSubmit={mockOnSubmit}
                onCancel={mockOnCancel}
            />
        );

        expect(screen.getByText('Edit Secret')).toBeInTheDocument();
        expect(screen.getByDisplayValue('test-secret')).toBeInTheDocument();
        expect(screen.getByDisplayValue('password')).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Update Secret' })).toBeInTheDocument();
    });

    it('validates required fields', async () => {
        render(
            <SecretForm
                mode="create"
                onSubmit={mockOnSubmit}
                onCancel={mockOnCancel}
            />
        );

        const submitButton = screen.getByRole('button', { name: 'Create Secret' });
        fireEvent.click(submitButton);

        await waitFor(() => {
            expect(screen.getByText('Name is required')).toBeInTheDocument();
            expect(screen.getByText('Value is required')).toBeInTheDocument();
        });

        expect(mockOnSubmit).not.toHaveBeenCalled();
    });

    it('validates name format', async () => {
        render(
            <SecretForm
                mode="create"
                onSubmit={mockOnSubmit}
                onCancel={mockOnCancel}
            />
        );

        const nameInput = screen.getByLabelText('Name');
        fireEvent.change(nameInput, { target: { value: 'Invalid Name!' } });
        fireEvent.blur(nameInput);

        await waitFor(() => {
            expect(screen.getByText(/Name must contain only/)).toBeInTheDocument();
        });
    });

    it('submits form with valid data', async () => {
        render(
            <SecretForm
                mode="create"
                onSubmit={mockOnSubmit}
                onCancel={mockOnCancel}
            />
        );

        // Fill in the form
        fireEvent.change(screen.getByLabelText('Name'), {
            target: { value: 'test-secret' }
        });
        fireEvent.change(screen.getByLabelText('Value'), {
            target: { value: 'secret-value' }
        });
        fireEvent.change(screen.getByLabelText('Namespace'), {
            target: { value: 'production' }
        });

        const submitButton = screen.getByRole('button', { name: 'Create Secret' });
        fireEvent.click(submitButton);

        await waitFor(() => {
            expect(mockOnSubmit).toHaveBeenCalledWith({
                name: 'test-secret',
                type: 'text',
                value: 'secret-value',
                namespace: 'production',
                zone: '',
                environment: '',
                tags: [],
                metadata: {},
            });
        });
    });

    it('handles cancel action', () => {
        render(
            <SecretForm
                mode="create"
                onSubmit={mockOnSubmit}
                onCancel={mockOnCancel}
            />
        );

        const cancelButton = screen.getByRole('button', { name: 'Cancel' });
        fireEvent.click(cancelButton);

        expect(mockOnCancel).toHaveBeenCalled();
    });

    it('shows loading state during submission', async () => {
        const slowSubmit = vi.fn(() => new Promise(resolve => setTimeout(resolve, 100)));

        render(
            <SecretForm
                mode="create"
                onSubmit={slowSubmit}
                onCancel={mockOnCancel}
            />
        );

        // Fill in required fields
        fireEvent.change(screen.getByLabelText('Name'), {
            target: { value: 'test-secret' }
        });
        fireEvent.change(screen.getByLabelText('Value'), {
            target: { value: 'secret-value' }
        });

        const submitButton = screen.getByRole('button', { name: 'Create Secret' });
        fireEvent.click(submitButton);

        expect(screen.getByText('Creating...')).toBeInTheDocument();
        expect(submitButton).toBeDisabled();

        await waitFor(() => {
            expect(slowSubmit).toHaveBeenCalled();
        });
    });

    it('handles different secret types', () => {
        render(
            <SecretForm
                mode="create"
                onSubmit={mockOnSubmit}
                onCancel={mockOnCancel}
            />
        );

        const typeSelect = screen.getByLabelText('Type');

        // Test password type
        fireEvent.change(typeSelect, { target: { value: 'password' } });
        expect(screen.getByLabelText('Value')).toHaveAttribute('type', 'password');

        // Test JSON type
        fireEvent.change(typeSelect, { target: { value: 'json' } });
        expect(screen.getByLabelText('Value')).toHaveAttribute('rows');
    });

    it('manages tags correctly', async () => {
        render(
            <SecretForm
                mode="create"
                onSubmit={mockOnSubmit}
                onCancel={mockOnCancel}
            />
        );

        const tagInput = screen.getByLabelText('Tags');
        fireEvent.change(tagInput, { target: { value: 'tag1,tag2,tag3' } });

        // Fill other required fields
        fireEvent.change(screen.getByLabelText('Name'), {
            target: { value: 'test-secret' }
        });
        fireEvent.change(screen.getByLabelText('Value'), {
            target: { value: 'secret-value' }
        });

        const submitButton = screen.getByRole('button', { name: 'Create Secret' });
        fireEvent.click(submitButton);

        await waitFor(() => {
            expect(mockOnSubmit).toHaveBeenCalledWith(
                expect.objectContaining({
                    tags: ['tag1', 'tag2', 'tag3']
                })
            );
        });
    });
});