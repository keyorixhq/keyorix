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
            expect(mockPost).toHaveBeenCalledWith('/api/v1/projects/1/environments/2/copy-secrets', {
                target_environment_id: 3,
            })
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

    it('POSTs extend-expiring when "Extend all" is clicked', async () => {
        // Surface the Expiring-secrets section by returning one expiring secret.
        mockGet.mockImplementation((url: string) =>
            url.includes('/secrets/expiring')
                ? Promise.resolve({
                      data: { data: { expiring: [{ id: 9, name: 'db', type: 'password', expired: true }] } },
                  })
                : Promise.resolve({ data: { data: {} } })
        );
        mockPost.mockResolvedValue({ data: { data: { extended: 1 } } });

        render(<ProjectSettingsTab projectId={1} />);
        fireEvent.click(await screen.findByRole('button', { name: /extend all/i }));

        await waitFor(() => expect(mockPost).toHaveBeenCalledWith('/api/v1/projects/1/secrets/extend-expiring', {}));
        expect(await screen.findByText(/renewed 1 secret/i)).toBeInTheDocument();
    });

    it('fetches the inventory CSV as a blob when Export inventory is clicked', async () => {
        mockGet.mockResolvedValue({ data: new Blob(['id,name\n'], { type: 'text/csv' }) });

        render(<ProjectSettingsTab projectId={1} />);
        fireEvent.click(screen.getByRole('button', { name: /export inventory/i }));

        await waitFor(() =>
            expect(mockGet).toHaveBeenCalledWith('/api/v1/projects/1/secrets/inventory.csv', { responseType: 'blob' })
        );
        expect((URL as any).createObjectURL).toHaveBeenCalled();
    });

    it('shows naming-policy violations with their reason when the policy flags a name', async () => {
        mockGet.mockImplementation((url: string) =>
            url.includes('/secrets/name-conformance')
                ? Promise.resolve({
                      data: {
                          data: {
                              policy_enabled: true,
                              total_secrets: 2,
                              violations: [
                                  {
                                      id: 8,
                                      name: 'db-pass',
                                      type: 'password',
                                      reason: 'secret name does not match the required pattern',
                                  },
                              ],
                          },
                      },
                  })
                : Promise.resolve({ data: { data: {} } })
        );

        render(<ProjectSettingsTab projectId={1} />);

        expect(await screen.findByText('Naming-policy violations')).toBeInTheDocument();
        // The current name is prefilled into an editable rename input.
        expect(screen.getByDisplayValue('db-pass')).toBeInTheDocument();
        expect(screen.getByText(/does not match the required pattern/i)).toBeInTheDocument();
    });

    it('hides the naming-policy section when there are no violations', async () => {
        mockGet.mockResolvedValue({ data: { data: { policy_enabled: false, total_secrets: 0, violations: [] } } });

        render(<ProjectSettingsTab projectId={1} />);

        // The recycle-bin section always renders, so the page is settled.
        expect(await screen.findByText('Recycle bin')).toBeInTheDocument();
        expect(screen.queryByText('Naming-policy violations')).not.toBeInTheDocument();
    });

    it('POSTs bulk-rename with only the edited rows, then reports the result', async () => {
        mockGet.mockImplementation((url: string) =>
            url.includes('/secrets/name-conformance')
                ? Promise.resolve({
                      data: {
                          data: {
                              policy_enabled: true,
                              total_secrets: 2,
                              violations: [
                                  {
                                      id: 8,
                                      name: 'db-pass',
                                      type: 'password',
                                      reason: 'does not match the required pattern',
                                  },
                              ],
                          },
                      },
                  })
                : Promise.resolve({ data: { data: {} } })
        );
        mockPost.mockResolvedValue({
            data: {
                data: {
                    dry_run: false,
                    renamed: 1,
                    skipped: 0,
                    outcomes: [{ id: 8, old_name: 'db-pass', new_name: 'DB_PASS', status: 'renamed' }],
                },
            },
        });

        render(<ProjectSettingsTab projectId={1} />);

        const input = await screen.findByDisplayValue('db-pass');
        // Apply is disabled until a name is actually edited.
        const applyBtn = screen.getByRole('button', { name: /Apply renames/i });
        expect(applyBtn).toBeDisabled();

        fireEvent.change(input, { target: { value: 'DB_PASS' } });
        expect(screen.getByRole('button', { name: /Apply renames \(1\)/i })).toBeEnabled();
        fireEvent.click(screen.getByRole('button', { name: /Apply renames/i }));

        await waitFor(() =>
            expect(mockPost).toHaveBeenCalledWith('/api/v1/projects/1/secrets/bulk-rename', {
                renames: [{ id: 8, new_name: 'DB_PASS' }],
                dry_run: false,
            })
        );
        expect(await screen.findByText(/Renamed 1 secret/i)).toBeInTheDocument();
    });

    it('surfaces the reason for a skipped rename', async () => {
        mockGet.mockImplementation((url: string) =>
            url.includes('/secrets/name-conformance')
                ? Promise.resolve({
                      data: {
                          data: {
                              policy_enabled: true,
                              total_secrets: 1,
                              violations: [
                                  {
                                      id: 8,
                                      name: 'db-pass',
                                      type: 'password',
                                      reason: 'does not match the required pattern',
                                  },
                              ],
                          },
                      },
                  })
                : Promise.resolve({ data: { data: {} } })
        );
        mockPost.mockResolvedValue({
            data: {
                data: {
                    dry_run: false,
                    renamed: 0,
                    skipped: 1,
                    outcomes: [
                        {
                            id: 8,
                            old_name: 'db-pass',
                            new_name: 'still-bad',
                            status: 'skipped',
                            reason: 'secret name does not match the required pattern',
                        },
                    ],
                },
            },
        });

        render(<ProjectSettingsTab projectId={1} />);

        fireEvent.change(await screen.findByDisplayValue('db-pass'), { target: { value: 'still-bad' } });
        fireEvent.click(screen.getByRole('button', { name: /Apply renames/i }));

        // The summary carries the count and the per-skip reason from the server.
        expect(
            await screen.findByText(/0 secret\(s\), 1 skipped.*does not match the required pattern/i)
        ).toBeInTheDocument();
    });
});
