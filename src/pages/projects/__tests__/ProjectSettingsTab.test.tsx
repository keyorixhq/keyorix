import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '../../../test/test-utils';
import { ProjectSettingsTab } from '../ProjectSettingsTab';

const mockPost = vi.fn();
const mockGet = vi.fn();

vi.mock('../../../services/client', () => ({
    apiClient: {
        get: (...args: any[]) => mockGet(...args),
        post: (...args: any[]) => mockPost(...args),
        put: vi.fn().mockResolvedValue({ data: { data: {} } }),
        delete: vi.fn().mockResolvedValue({ data: { data: {} } }),
    },
}));

beforeEach(() => {
    // jsdom has no object-URL API; stub it for the inventory download.
    (URL as any).createObjectURL = vi.fn(() => 'blob:mock');
    (URL as any).revokeObjectURL = vi.fn();
});

vi.mock('../../../features/projects/api', () => ({
    PROJECT_KEYS: { all: ['projects'] },
    useProject: () => ({ data: { id: 1, name: 'web', description: '' }, isLoading: false }),
    useProjectEnvironments: () => ({
        data: [
            { id: 2, name: 'staging' },
            { id: 3, name: 'production' },
        ],
        isLoading: false,
    }),
    useRestoreEnvironment: () => ({ mutate: vi.fn(), isPending: false }),
}));

describe('ProjectSettingsTab — promote environment', () => {
    beforeEach(() => {
        mockPost.mockReset();
        mockGet.mockReset();
        mockGet.mockResolvedValue({ data: { data: {} } });
    });

    it('POSTs copy-secrets with the prompted target environment id', async () => {
        mockPost.mockResolvedValue({ data: { data: { copied: 4, skipped: 1 } } });
        const promptSpy = vi.spyOn(window, 'prompt').mockReturnValue('3');

        render(<ProjectSettingsTab projectId={1} />);

        // One Promote button per active environment; click staging's (id 2).
        const promoteButtons = screen.getAllByTitle(/Promote/i);
        fireEvent.click(promoteButtons[0]);

        await waitFor(() =>
            expect(mockPost).toHaveBeenCalledWith(
                '/api/v1/projects/1/environments/2/copy-secrets',
                { target_environment_id: 3 }
            )
        );
        expect(await screen.findByText(/4 copied, 1 skipped/i)).toBeInTheDocument();
        promptSpy.mockRestore();
    });

    it('refuses to promote an environment into itself', () => {
        const promptSpy = vi.spyOn(window, 'prompt').mockReturnValue('2');

        render(<ProjectSettingsTab projectId={1} />);
        fireEvent.click(screen.getAllByTitle(/Promote/i)[0]); // staging id 2, target 2

        expect(mockPost).not.toHaveBeenCalled();
        expect(screen.getByText(/must differ/i)).toBeInTheDocument();
        promptSpy.mockRestore();
    });

    it('fetches the inventory CSV as a blob when Export inventory is clicked', async () => {
        mockGet.mockResolvedValue({ data: new Blob(['id,name\n'], { type: 'text/csv' }) });

        render(<ProjectSettingsTab projectId={1} />);
        fireEvent.click(screen.getByRole('button', { name: /export inventory/i }));

        await waitFor(() =>
            expect(mockGet).toHaveBeenCalledWith(
                '/api/v1/projects/1/secrets/inventory.csv',
                { responseType: 'blob' }
            )
        );
        expect((URL as any).createObjectURL).toHaveBeenCalled();
    });
});
