import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, within } from '../../../test/test-utils';
import { ProjectSecretsTab } from '../ProjectSecretsTab';

const {
    createMutate,
    editMutate,
    deleteMutate,
    rotateMutate,
    refetchMock,
    setSearchMock,
    setTypeFilterMock,
    handlePageChangeMock,
    handlePageSizeChangeMock,
} = vi.hoisted(() => ({
    createMutate: vi.fn(),
    editMutate: vi.fn(),
    deleteMutate: vi.fn(),
    rotateMutate: vi.fn(),
    refetchMock: vi.fn(),
    setSearchMock: vi.fn(),
    setTypeFilterMock: vi.fn(),
    handlePageChangeMock: vi.fn(),
    handlePageSizeChangeMock: vi.fn(),
}));

const listState = vi.hoisted(() => ({
    secrets: [] as any[],
    isLoading: false,
    error: null as unknown,
    isFetching: false,
    search: '',
    typeFilter: 'all',
    pagination: { page: 1, pageSize: 20, total: 0, totalPages: 1 },
    createMutation: { isPending: false, isError: false, error: null as unknown },
    editMutation: { isPending: false, isError: false, error: null as unknown },
    deleteMutation: { isPending: false, isError: false, error: null as unknown },
    rotateMutation: { isPending: false, isError: false, error: null as unknown },
}));

const envState = vi.hoisted(() => ({ data: [] as any[], isLoading: false }));

vi.mock('../../../features/secrets/useProjectSecrets', () => ({
    useProjectSecrets: () => {
        const [activeModal, setActiveModalState] = React.useState<string | null>(null);
        const [modalData, setModalData] = React.useState<any>(null);
        const openModal = (id: string, data: any = null) => {
            setActiveModalState(id);
            setModalData(data);
        };
        const closeModal = () => {
            setActiveModalState(null);
            setModalData(null);
        };
        return {
            secrets: listState.secrets,
            isLoading: listState.isLoading,
            error: listState.error,
            refetch: refetchMock,
            isFetching: listState.isFetching,
            search: listState.search,
            setSearch: setSearchMock,
            typeFilter: listState.typeFilter,
            setTypeFilter: setTypeFilterMock,
            pagination: listState.pagination,
            handlePageChange: handlePageChangeMock,
            handlePageSizeChange: handlePageSizeChangeMock,
            createMutation: { mutate: createMutate, ...listState.createMutation },
            editMutation: { mutate: editMutate, ...listState.editMutation },
            deleteMutation: { mutate: deleteMutate, ...listState.deleteMutation },
            rotateMutation: { mutate: rotateMutate, ...listState.rotateMutation },
            openModal,
            closeModal,
            activeModal,
            modalData,
        };
    },
}));

vi.mock('../../../features/projects/api', () => ({
    useProjectEnvironments: () => ({ data: envState.data, isLoading: envState.isLoading }),
}));

vi.mock('../../../features/secrets', () => ({
    useSecretReveal: () => ({
        copyingSecretId: null,
        copiedSecretId: null,
        copyErrorId: null,
        handleCopySecretValue: vi.fn(),
    }),
    SecretTableRow: ({ secret, isSelected, onToggleSelect, onView, onEdit, onDelete, onShare, onRotate }: any) => (
        <tr>
            <td>
                <input
                    type="checkbox"
                    aria-label={`select ${secret.name}`}
                    checked={isSelected}
                    onChange={() => onToggleSelect(secret.id)}
                />
            </td>
            <td>{secret.name}</td>
            <td>
                <button onClick={() => onView(secret)}>View {secret.name}</button>
                <button onClick={() => onEdit(secret)}>Edit {secret.name}</button>
                <button onClick={() => onDelete(secret)}>Delete {secret.name}</button>
                <button onClick={() => onShare(secret)}>Share {secret.name}</button>
                <button onClick={() => onRotate(secret)}>Rotate {secret.name}</button>
            </td>
        </tr>
    ),
    SecretDetailView: ({ secret, onClose, onEdit, onShare, onDelete }: any) => (
        <div>
            <p>Detail: {secret.name}</p>
            <button onClick={() => onEdit(secret)}>Detail Edit</button>
            <button onClick={() => onShare(secret)}>Detail Share</button>
            <button onClick={() => onDelete(secret)}>Detail Delete</button>
            <button onClick={onClose}>Detail Close</button>
        </div>
    ),
}));

vi.mock('../../../features/sharing', () => ({
    ShareSecretModal: ({ secret, onClose, onSuccess }: any) => (
        <div role="dialog" aria-label="share-modal">
            <p>Share: {secret.name}</p>
            <button onClick={onClose}>Close Share</button>
            <button onClick={onSuccess}>Share Success</button>
        </div>
    ),
}));

vi.mock('../SecretsDriftPanel', () => ({
    SecretsDriftPanel: () => <div>Drift Panel Content</div>,
}));

vi.mock('../SecretsRotationPlanPanel', () => ({
    SecretsRotationPlanPanel: () => <div>Rotation Plan Content</div>,
}));

const twoEnvs = [
    { id: 2, name: 'staging', projectId: 1 },
    { id: 3, name: 'production', projectId: 1 },
];

const secretsFixture = [
    { id: 1, name: 'db-pass', type: 'password' },
    { id: 2, name: 'api-key', type: 'api_key' },
];

function resetState() {
    listState.secrets = [];
    listState.isLoading = false;
    listState.error = null;
    listState.isFetching = false;
    listState.search = '';
    listState.typeFilter = 'all';
    listState.pagination = { page: 1, pageSize: 20, total: 0, totalPages: 1 };
    listState.createMutation = { isPending: false, isError: false, error: null };
    listState.editMutation = { isPending: false, isError: false, error: null };
    listState.deleteMutation = { isPending: false, isError: false, error: null };
    listState.rotateMutation = { isPending: false, isError: false, error: null };
    envState.data = [];
    envState.isLoading = false;
}

beforeEach(() => {
    vi.clearAllMocks();
    resetState();
    window.history.pushState({}, '', '/');
});

describe('ProjectSecretsTab — environment selection', () => {
    it('defaults to the production environment when present', () => {
        envState.data = twoEnvs;
        render(<ProjectSecretsTab projectId={1} />);
        expect(screen.getByText('No secrets in production')).toBeInTheDocument();
    });

    it('defaults to the first environment when there is no production environment', () => {
        envState.data = [{ id: 5, name: 'dev', projectId: 1 }];
        render(<ProjectSecretsTab projectId={1} />);
        expect(screen.getByText('No secrets in dev')).toBeInTheDocument();
    });

    it('switches the active environment when a pill is clicked', () => {
        envState.data = twoEnvs;
        render(<ProjectSecretsTab projectId={1} />);
        fireEvent.click(screen.getByRole('button', { name: 'Staging' }));
        expect(screen.getByText('No secrets in staging')).toBeInTheDocument();
    });
});

describe('ProjectSecretsTab — secrets table', () => {
    it('shows a loading indicator while secrets are loading', () => {
        listState.isLoading = true;
        render(<ProjectSecretsTab projectId={1} />);
        expect(screen.getByText('Loading...')).toBeInTheDocument();
    });

    it('shows an empty state with a New Secret action when there are no secrets', () => {
        render(<ProjectSecretsTab projectId={1} />);
        expect(screen.getByText('No secrets in production')).toBeInTheDocument();
        expect(screen.getByText('Create your first secret in this environment.')).toBeInTheDocument();
    });

    it('renders secret rows', () => {
        listState.secrets = secretsFixture;
        render(<ProjectSecretsTab projectId={1} />);
        expect(screen.getByText('db-pass')).toBeInTheDocument();
        expect(screen.getByText('api-key')).toBeInTheDocument();
    });

    it('shows an error state and retries', () => {
        listState.error = new Error('boom');
        render(<ProjectSecretsTab projectId={1} />);
        expect(screen.getByText('Failed to load secrets')).toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: /retry/i }));
        expect(refetchMock).toHaveBeenCalled();
    });

    it('shows a fetching indicator when refetching in the background', () => {
        listState.secrets = secretsFixture;
        listState.isFetching = true;
        render(<ProjectSecretsTab projectId={1} />);
        expect(screen.getByText('Updating…')).toBeInTheDocument();
    });
});

describe('ProjectSecretsTab — toolbar', () => {
    it('reports search input changes to the list hook', () => {
        render(<ProjectSecretsTab projectId={1} />);
        fireEvent.change(screen.getByPlaceholderText('Search secrets…'), { target: { value: 'db' } });
        expect(setSearchMock).toHaveBeenCalledWith('db');
    });

    it('reports type filter changes to the list hook', () => {
        render(<ProjectSecretsTab projectId={1} />);
        const [typeSelect] = screen.getAllByRole('combobox');
        fireEvent.change(typeSelect, { target: { value: 'password' } });
        expect(setTypeFilterMock).toHaveBeenCalledWith('password');
    });

    it('reports page size changes to the list hook', () => {
        render(<ProjectSecretsTab projectId={1} />);
        const [, pageSizeSelect] = screen.getAllByRole('combobox');
        fireEvent.change(pageSizeSelect, { target: { value: '50' } });
        expect(handlePageSizeChangeMock).toHaveBeenCalledWith(50);
    });
});

describe('ProjectSecretsTab — pagination', () => {
    it('navigates pages and disables edges', () => {
        listState.secrets = secretsFixture;
        listState.pagination = { page: 1, pageSize: 20, total: 40, totalPages: 2 };
        render(<ProjectSecretsTab projectId={1} />);

        expect(screen.getByText('1 / 2')).toBeInTheDocument();
        const [prevButton, nextButton] = screen.getAllByRole('button', { name: '' });
        expect(prevButton).toBeDisabled();

        fireEvent.click(nextButton);
        expect(handlePageChangeMock).toHaveBeenCalledWith(2);
    });
});

describe('ProjectSecretsTab — bulk selection', () => {
    it('tracks selected rows and clears them', () => {
        listState.secrets = secretsFixture;
        render(<ProjectSecretsTab projectId={1} />);

        fireEvent.click(screen.getByLabelText('select db-pass'));
        expect(screen.getByText('1 selected')).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Clear' }));
        expect(screen.queryByText('1 selected')).not.toBeInTheDocument();
    });

    it('selects all rows via the header checkbox', () => {
        listState.secrets = secretsFixture;
        render(<ProjectSecretsTab projectId={1} />);

        const headerCheckbox = within(screen.getByRole('table')).getAllByRole('checkbox')[0]!;
        fireEvent.click(headerCheckbox);
        expect(screen.getByText('2 selected')).toBeInTheDocument();
    });
});

describe('ProjectSecretsTab — create secret', () => {
    it('creates a secret with the active environment id and resets the form', () => {
        envState.data = twoEnvs;
        render(<ProjectSecretsTab projectId={1} />);

        fireEvent.click(screen.getAllByRole('button', { name: /new secret/i })[0]!);
        fireEvent.change(screen.getByLabelText(/^Name/), { target: { value: 'new-secret' } });
        fireEvent.change(screen.getByLabelText(/^Value/), { target: { value: 'super-secret-value' } });
        fireEvent.click(screen.getByRole('button', { name: 'Create Secret' }));

        expect(createMutate).toHaveBeenCalledWith(
            {
                name: 'new-secret',
                value: 'super-secret-value',
                type: 'text',
                project_id: 1,
                environment_id: 3,
            },
            expect.objectContaining({ onSuccess: expect.any(Function) })
        );
    });

    it('discards the draft when Cancel is clicked', () => {
        render(<ProjectSecretsTab projectId={1} />);

        fireEvent.click(screen.getAllByRole('button', { name: /new secret/i })[0]!);
        fireEvent.change(screen.getByLabelText(/^Name/), { target: { value: 'draft-name' } });
        fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));

        fireEvent.click(screen.getAllByRole('button', { name: /new secret/i })[0]!);
        expect(screen.getByLabelText(/^Name/)).toHaveValue('');
    });
});

describe('ProjectSecretsTab — view / edit / delete / rotate / share', () => {
    it('opens the view modal and navigates to edit from it', () => {
        listState.secrets = secretsFixture;
        render(<ProjectSecretsTab projectId={1} />);

        fireEvent.click(screen.getByText('View db-pass'));
        expect(screen.getByText('Detail: db-pass')).toBeInTheDocument();

        fireEvent.click(screen.getByText('Detail Edit'));
        expect(screen.getByText('Edit Secret: db-pass')).toBeInTheDocument();
        expect(screen.queryByText('Detail: db-pass')).not.toBeInTheDocument();
    });

    it('prefills and submits the edit form', () => {
        listState.secrets = secretsFixture;
        render(<ProjectSecretsTab projectId={1} />);

        fireEvent.click(screen.getByText('Edit db-pass'));
        expect(screen.getByLabelText('Name')).toHaveValue('db-pass');

        fireEvent.click(screen.getByRole('button', { name: 'Save Changes' }));
        expect(editMutate).toHaveBeenCalledWith({ id: 1, name: 'db-pass', type: 'password', value: '' });
    });

    it('deletes a secret after confirming', () => {
        listState.secrets = secretsFixture;
        render(<ProjectSecretsTab projectId={1} />);

        fireEvent.click(screen.getByText('Delete db-pass'));
        expect(screen.getByText('Delete Secret')).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Delete' }));
        expect(deleteMutate).toHaveBeenCalledWith(1);
    });

    it('rotates a secret with a generated value', () => {
        listState.secrets = secretsFixture;
        render(<ProjectSecretsTab projectId={1} />);

        fireEvent.click(screen.getByText('Rotate db-pass'));
        expect(screen.getByText('Rotate: db-pass')).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Rotate' }));
        expect(rotateMutate).toHaveBeenCalledWith({ id: 1, newValue: expect.any(String) });
    });

    it('shares a secret and refetches on success', () => {
        listState.secrets = secretsFixture;
        render(<ProjectSecretsTab projectId={1} />);

        fireEvent.click(screen.getByText('Share db-pass'));
        expect(screen.getByText('Share: db-pass')).toBeInTheDocument();

        fireEvent.click(screen.getByText('Share Success'));
        expect(refetchMock).toHaveBeenCalled();
        expect(screen.queryByText('Share: db-pass')).not.toBeInTheDocument();
    });
});

describe('ProjectSecretsTab — drift & rotation plan reports', () => {
    it('opens the drift report', () => {
        render(<ProjectSecretsTab projectId={1} />);
        fireEvent.click(screen.getByRole('button', { name: /check drift/i }));
        expect(screen.getByText('Drift Panel Content')).toBeInTheDocument();
    });

    it('opens the rotation plan report', () => {
        render(<ProjectSecretsTab projectId={1} />);
        fireEvent.click(screen.getByRole('button', { name: /rotation plan/i }));
        expect(screen.getByText('Rotation Plan Content')).toBeInTheDocument();
    });
});
