import React, { useState, useMemo, useCallback } from 'react';
import { useQuery, useMutation, useQueryClient, keepPreviousData } from '@tanstack/react-query';
import { secretsApi } from '../../services/secrets';
import { queryKeys } from '../../lib/queryClient';
import { SecretType, SecretFormData } from '../../types';

const ITEMS_PER_PAGE = 20;

interface UseProjectSecretsOptions {
    projectId: number;
    environmentId: number | null;
}

/**
 * Like useSecretsList but scoped to a specific project + environment.
 * Uses local modal state (not global UIStore) to avoid conflicts with AllSecretsPage.
 */
export const useProjectSecrets = ({ projectId, environmentId }: UseProjectSecretsOptions) => {
    const queryClient = useQueryClient();

    // ── Local modal state (independent of global UIStore) ─────────────────
    const [activeModal, setActiveModal] = useState<string | null>(null);
    const [modalData, setModalData]     = useState<any>(null);
    const openModal  = useCallback((modalId: string, data: any = null) => { setActiveModal(modalId); setModalData(data); }, []);
    const closeModal = useCallback(() => { setActiveModal(null); setModalData(null); }, []);

    const [search, setSearch] = useState('');
    const [debouncedSearch, setDebouncedSearch] = useState('');
    const [typeFilter, setTypeFilter] = useState<SecretType | 'all'>('all');
    const [page, setPage] = useState(1);
    const [pageSize, setPageSize] = useState(ITEMS_PER_PAGE);

    // Debounce search
    React.useEffect(() => {
        const t = setTimeout(() => { setDebouncedSearch(search); setPage(1); }, 300);
        return () => clearTimeout(t);
    }, [search]);

    const queryKey = [
        'project-secrets', projectId, environmentId,
        debouncedSearch, typeFilter, page, pageSize,
    ];

    const { data, isLoading, error, refetch, isFetching } = useQuery({
        queryKey,
        queryFn: () => secretsApi.list({
            page,
            pageSize,
            ...(debouncedSearch ? { search: debouncedSearch } : {}),
            ...(typeFilter !== 'all' ? { type: typeFilter } : {}),
            project_id: projectId,
            ...(environmentId ? { environment_id: environmentId } : {}),
        }),
        enabled: projectId > 0,
        placeholderData: keepPreviousData,
    });

    const secrets = useMemo(() => data?.data ?? [], [data]);
    const pagination = {
        page,
        pageSize,
        total: data?.total ?? 0,
        totalPages: data?.totalPages ?? 1,
    };

    const handlePageChange = useCallback((p: number) => setPage(p), []);
    const handlePageSizeChange = useCallback((ps: number) => { setPageSize(ps); setPage(1); }, []);

    // Mutations — invalidate both global secrets and project-scoped key
    const invalidate = () => {
        queryClient.invalidateQueries({ queryKey: queryKeys.secrets.all });
        queryClient.invalidateQueries({ queryKey: ['project-secrets', projectId] });
    };

    const createMutation = useMutation({
        mutationFn: (d: any) => secretsApi.create(d),
        onSuccess: () => { closeModal(); invalidate(); },
    });

    const editMutation = useMutation({
        mutationFn: ({ id, name, type, value }: { id: number; name: string; type: SecretType; value: string }) => {
            const updateData: Partial<SecretFormData> = { name, type };
            if (value.trim()) updateData.value = value;
            return secretsApi.update(id, updateData);
        },
        onSuccess: () => { closeModal(); invalidate(); },
    });

    const deleteMutation = useMutation({
        mutationFn: (id: number) => secretsApi.delete(id),
        onSuccess: () => { closeModal(); invalidate(); },
    });

    const rotateMutation = useMutation({
        mutationFn: ({ id, newValue }: { id: number; newValue: string }) => secretsApi.rotate(id, newValue),
        onSuccess: () => { closeModal(); invalidate(); },
    });

    return {
        secrets, isLoading, error, refetch, isFetching,
        search, setSearch, typeFilter, setTypeFilter,
        pagination, handlePageChange, handlePageSizeChange,
        createMutation, editMutation, deleteMutation, rotateMutation,
        openModal, closeModal, activeModal, modalData,
    };
};
