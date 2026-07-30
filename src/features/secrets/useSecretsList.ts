import React, { useState, useMemo, useCallback } from 'react';
import { useQuery, useMutation, useQueryClient, keepPreviousData } from '@tanstack/react-query';
import { secretsApi } from '../../services/secrets';
import { environmentsApi } from '../../services/environments';
import { queryKeys } from '../../lib/queryClient';
import { SecretFilters, PaginationState, SecretType, SecretFormData } from '../../types';
import { useUIStore } from '../../store/uiStore';

const ITEMS_PER_PAGE = 20;

type Secret = {
    name: string;
    lastModified: string;
    type: string;
    Expiration?: string | null;
    [key: string]: any;
};

// Nulls sort last regardless of direction.
function compareExpiry(a: Secret, b: Secret): number {
    if (!a.Expiration && !b.Expiration) return 0;
    if (!a.Expiration) return 1;
    if (!b.Expiration) return -1;
    return new Date(a.Expiration).getTime() - new Date(b.Expiration).getTime();
}

function compareSecrets(a: Secret, b: Secret, sortField: string, sortDirection: string | undefined): number {
    if (sortField === 'expiry') {
        const cmp = compareExpiry(a, b);
        return sortDirection === 'asc' ? cmp : -cmp;
    }
    let aVal: any;
    let bVal: any;
    if (sortField === 'name') {
        aVal = a.name.toLowerCase();
        bVal = b.name.toLowerCase();
    } else if (sortField === 'modified') {
        aVal = new Date(a.lastModified);
        bVal = new Date(b.lastModified);
    } else if (sortField === 'type') {
        aVal = a.type;
        bVal = b.type;
    } else {
        return 0;
    }
    if (aVal < bVal) return sortDirection === 'asc' ? -1 : 1;
    if (aVal > bVal) return sortDirection === 'asc' ? 1 : -1;
    return 0;
}

function toggleSetItem(prev: Set<number>, id: number): Set<number> {
    const next = new Set(prev);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    return next;
}

function buildSecretQueryParams(
    filters: SecretFilters,
    page: number,
    pageSize: number,
    environmentIdMap: Record<string, number>
): Record<string, any> {
    const envId = filters.environment ? environmentIdMap[filters.environment] : undefined;
    return {
        page,
        pageSize,
        ...(filters.search ? { search: filters.search } : {}),
        ...(filters.type !== 'all' ? { type: filters.type } : {}),
        ...(filters.classification ? { classification: filters.classification } : {}),
        ...(envId ? { environment_id: envId } : {}),
        ...(filters.tags.length > 0 ? { tags: filters.tags } : {}),
    };
}

function buildEditUpdateData(name: string, type: SecretType, value: string): Partial<SecretFormData> {
    const updateData: Partial<SecretFormData> = { name, type };
    if (value.trim()) updateData.value = value;
    return updateData;
}

function computeHasActiveFilters(filters: SecretFilters): boolean {
    return !!(
        filters.search ||
        filters.type !== 'all' ||
        filters.classification ||
        filters.environment ||
        filters.tags.length > 0
    );
}

export const useSecretsList = () => {
    const { openModal, closeModal, activeModal, modalData } = useUIStore();
    const queryClient = useQueryClient();

    const [filters, setFilters] = useState<SecretFilters>({
        search: '',
        type: 'all',
        classification: '',
        environment: '',
        tags: [],
    });
    const [pagination, setPagination] = useState<PaginationState>({
        page: 1,
        pageSize: ITEMS_PER_PAGE,
        total: 0,
        totalPages: 0,
    });
    const [sortBy, setSortBy] = useState('modified_desc');
    const [tagInput, setTagInput] = useState('');
    const [showAdvancedFilters, setShowAdvancedFilters] = useState(false);
    const [searchInput, setSearchInput] = useState('');

    // Bulk selection
    const [selectedItems, setSelectedItems] = useState<Set<number>>(new Set());
    const [bulkActionMode, setBulkActionMode] = useState(false);
    const toggleSelectedItem = (id: number) => setSelectedItems((prev) => toggleSetItem(prev, id));
    const clearSelectedItems = () => setSelectedItems(new Set());

    const { data: environments = [] } = useQuery({
        queryKey: ['environments'],
        queryFn: () => environmentsApi.list(),
        staleTime: 5 * 60 * 1000,
    });

    const environmentIdMap = React.useMemo(() => {
        const map: Record<string, number> = {};
        environments.forEach((e) => {
            map[e.name] = e.id;
        });
        return map;
    }, [environments]);

    const { data, isLoading, error, refetch, isFetching } = useQuery({
        queryKey: queryKeys.secrets.list({
            ...filters,
            page: pagination.page,
            pageSize: pagination.pageSize,
            sortBy,
        }),
        queryFn: () =>
            secretsApi.list(buildSecretQueryParams(filters, pagination.page, pagination.pageSize, environmentIdMap)),
        placeholderData: keepPreviousData,
    });

    React.useEffect(() => {
        if (data) setPagination((prev) => ({ ...prev, total: data.total, totalPages: data.totalPages }));
    }, [data]);

    const secrets = useMemo(() => {
        if (!data?.data) return [];
        const result = [...data.data];
        const [sortField = 'name', sortDirection] = sortBy.split('_');
        result.sort((a, b) => compareSecrets(a, b, sortField, sortDirection));
        return result;
    }, [data?.data, sortBy]);

    const handleFilterChange = useCallback((key: keyof SecretFilters, value: any) => {
        setFilters((prev) => ({ ...prev, [key]: value }));
        setPagination((prev) => ({ ...prev, page: 1 }));
    }, []);

    React.useEffect(() => {
        const timer = setTimeout(() => handleFilterChange('search', searchInput), 300);
        return () => clearTimeout(timer);
    }, [searchInput, handleFilterChange]);

    const handleAddTag = useCallback(
        (tag: string) => {
            if (tag.trim() && !filters.tags.includes(tag.trim()))
                handleFilterChange('tags', [...filters.tags, tag.trim()]);
            setTagInput('');
        },
        [filters.tags, handleFilterChange]
    );

    const handleRemoveTag = useCallback(
        (tagToRemove: string) => {
            handleFilterChange(
                'tags',
                filters.tags.filter((t) => t !== tagToRemove)
            );
        },
        [filters.tags, handleFilterChange]
    );

    const handleTagInputKeyPress = useCallback(
        (e: React.KeyboardEvent) => {
            if (e.key === 'Enter' && tagInput.trim()) {
                e.preventDefault();
                handleAddTag(tagInput);
            }
        },
        [tagInput, handleAddTag]
    );

    const handlePageChange = useCallback((page: number) => setPagination((prev) => ({ ...prev, page })), []);
    const handlePageSizeChange = useCallback(
        (pageSize: number) => setPagination((prev) => ({ ...prev, pageSize, page: 1 })),
        []
    );

    const handleClearFilters = useCallback(() => {
        setFilters({ search: '', type: 'all', classification: '', environment: '', tags: [] });
        setSearchInput('');
        setTagInput('');
        setPagination((prev) => ({ ...prev, page: 1 }));
    }, []);

    const hasActiveFilters = useMemo(() => computeHasActiveFilters(filters), [filters]);

    // Mutations
    const createMutation = useMutation({
        mutationFn: (d: SecretFormData) => secretsApi.create(d),
        onSuccess: () => {
            closeModal();
            queryClient.invalidateQueries({ queryKey: queryKeys.secrets.all });
        },
    });

    const editMutation = useMutation({
        mutationFn: ({ id, name, type, value }: { id: number; name: string; type: SecretType; value: string }) =>
            secretsApi.update(id, buildEditUpdateData(name, type, value)),
        onSuccess: () => {
            closeModal();
            queryClient.invalidateQueries({ queryKey: queryKeys.secrets.all });
        },
    });

    const deleteMutation = useMutation({
        mutationFn: (id: number) => secretsApi.delete(id),
        onSuccess: () => {
            closeModal();
            queryClient.invalidateQueries({ queryKey: queryKeys.secrets.all });
        },
    });

    const rotateMutation = useMutation({
        mutationFn: ({ id, newValue }: { id: number; newValue: string }) => secretsApi.rotate(id, newValue),
        onSuccess: () => {
            closeModal();
            queryClient.invalidateQueries({ queryKey: queryKeys.secrets.all });
        },
    });

    const bulkDeleteMutation = useMutation({
        mutationFn: (ids: number[]) => Promise.all(ids.map((id) => secretsApi.delete(id))),
        onSuccess: () => {
            closeModal();
            clearSelectedItems();
            setBulkActionMode(false);
            queryClient.invalidateQueries({ queryKey: queryKeys.secrets.all });
        },
    });

    return {
        secrets,
        data,
        isLoading,
        error,
        refetch,
        isFetching,
        filters,
        setFilters,
        pagination,
        setPagination,
        sortBy,
        setSortBy,
        tagInput,
        setTagInput,
        searchInput,
        setSearchInput,
        showAdvancedFilters,
        setShowAdvancedFilters,
        selectedItems,
        bulkActionMode,
        setBulkActionMode,
        toggleSelectedItem,
        clearSelectedItems,
        environments,
        handleFilterChange,
        handleAddTag,
        handleRemoveTag,
        handleTagInputKeyPress,
        handlePageChange,
        handlePageSizeChange,
        handleClearFilters,
        hasActiveFilters,
        createMutation,
        editMutation,
        deleteMutation,
        rotateMutation,
        bulkDeleteMutation,
        openModal,
        closeModal,
        activeModal,
        modalData,
    };
};
