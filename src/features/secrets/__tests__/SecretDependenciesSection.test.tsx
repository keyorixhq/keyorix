import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '../../../test/test-utils';
import { Secret } from '../../../types';

const addMutateAsync = vi.fn().mockResolvedValue(undefined);
const removeMutate = vi.fn();

let depsData: any = { secret_id: 1, depends_on: [], dependents: [] };
let impactData: any = { secret_id: 1, secret_name: 'app-token', affected: [] };
let listData: any = { data: [], total: 0, page: 1, pageSize: 20, totalPages: 1 };

vi.mock('../api', () => ({
    useSecretDependencies: () => ({ data: depsData }),
    useSecretImpact: () => ({ data: impactData }),
    useSecrets: () => ({ data: listData }),
    useAddSecretDependency: () => ({ mutateAsync: addMutateAsync, isPending: false }),
    useRemoveSecretDependency: () => ({ mutate: removeMutate, isPending: false }),
}));

import { SecretDependenciesSection } from '../SecretDependenciesSection';

const makeSecret = (overrides: Partial<Secret> = {}): Secret => ({
    id: 1,
    name: 'app-token',
    type: 'api_key',
    projectId: 7,
    environment: 'production',
    isShared: false,
    shareCount: 0,
    lastModified: '2026-06-22T00:00:00Z',
    owner: 'alice',
    permissions: [],
    metadata: {},
    tags: [],
    classification: 'confidential',
    ...overrides,
});

describe('SecretDependenciesSection', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        depsData = { secret_id: 1, depends_on: [], dependents: [] };
        impactData = { secret_id: 1, secret_name: 'app-token', affected: [] };
        listData = { data: [], total: 0, page: 1, pageSize: 20, totalPages: 1 };
    });

    it('shows empty states when there are no dependencies', () => {
        render(<SecretDependenciesSection secret={makeSecret()} />);
        expect(screen.getByText(/Rotating this secret affects no other secrets/i)).toBeInTheDocument();
        expect(screen.getByText(/this secret stands alone/i)).toBeInTheDocument();
        expect(screen.getByText(/No other secret depends on this one/i)).toBeInTheDocument();
    });

    it('renders dependencies, dependents, and the blast radius', () => {
        depsData = {
            secret_id: 1,
            depends_on: [{ id: 10, secret_id: 2, secret_name: 'db-password', note: 'derives from' }],
            dependents: [{ id: 11, secret_id: 3, secret_name: 'edge-cert' }],
        };
        impactData = {
            secret_id: 1,
            secret_name: 'app-token',
            affected: [{ secret_id: 3, secret_name: 'edge-cert', depth: 1 }],
        };
        render(<SecretDependenciesSection secret={makeSecret()} />);

        expect(screen.getByText('db-password')).toBeInTheDocument();
        expect(screen.getByText(/derives from/)).toBeInTheDocument();
        expect(screen.getByText(/affects 1 other secret:/i)).toBeInTheDocument();
        // edge-cert appears both as a dependent and in the blast radius.
        expect(screen.getAllByText('edge-cert').length).toBeGreaterThanOrEqual(1);
    });

    it('removes an edge via the mutation', () => {
        depsData = {
            secret_id: 1,
            depends_on: [{ id: 10, secret_id: 2, secret_name: 'db-password' }],
            dependents: [],
        };
        render(<SecretDependenciesSection secret={makeSecret()} />);
        fireEvent.click(screen.getByText('Remove'));
        expect(removeMutate).toHaveBeenCalledWith(10);
    });

    it('only offers same project + environment secrets as candidates, and adds one', async () => {
        listData = {
            data: [
                makeSecret({ id: 2, name: 'db-password' }), // same project+env → candidate
                makeSecret({ id: 5, name: 'other-project', projectId: 99 }), // different project → excluded
                makeSecret({ id: 6, name: 'other-env', environment: 'staging' }), // different env → excluded
            ],
            total: 3,
            page: 1,
            pageSize: 20,
            totalPages: 1,
        };
        render(<SecretDependenciesSection secret={makeSecret()} />);

        expect(screen.getByRole('option', { name: 'db-password' })).toBeInTheDocument();
        expect(screen.queryByRole('option', { name: 'other-project' })).not.toBeInTheDocument();
        expect(screen.queryByRole('option', { name: 'other-env' })).not.toBeInTheDocument();

        fireEvent.change(screen.getByRole('combobox'), { target: { value: '2' } });
        fireEvent.click(screen.getByText('Add'));
        expect(addMutateAsync).toHaveBeenCalledWith({ dependsOnId: 2 });
    });
});
