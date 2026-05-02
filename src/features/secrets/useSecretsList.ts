import React, { useState, useMemo, useCallback } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiService } from '../../services/api';
import { queryKeys } from '../../lib/queryClient';
import { Secret, SecretFilters, PaginationState, SecretType, SecretFormData } from '../../types';
import { useUIStore } from '../../store/uiStore';

const ITEMS_PER_PAGE = 20;

export const useSecretsList = () => {
    const { openModal, closeModal, activeModal, modalData } = useUIStore();
    const queryClient = useQueryClient();

    const [filters, setFilters] = useState<SecretFilters>({
        search: '', type: 'all', namespace: '', zone: '', environment: '', tags: [],
    });
    const [pagination, setPagination] = useState<PaginationState>({
        page: 1, pageSize: ITEMS_PER_PAGE, total: 0, totalPages: 0,
    });
    const [sortBy, setSortBy] = useState('modified_desc');
    const [tagInput, setTagInput] = useState('');
    const [showAdvancedFilters, setShowAdvancedFilters] = useState(false);
    const [searchInput, setSearchInput] = useState('');

    // Bulk selection
    const [selectedItems, setSelectedItems] = useState<Set<number>>(new Set());
    const [bulkActionMode, setBulkActionMode] = useState(false);
    const toggleSelectedItem = (id: number) => setSelectedItems(prev => {
        const next = new Set(prev);
        next.has(id) ? next.delete(id) : next.add(id);
        return next;
    });
    const clearSelectedItems = () => setSelectedItems(new Set());

    const { data: environments = [] } = useQuery({
        queryKey: ['environments'],
        queryFn: () => apiService.environments.list(),
        staleTime: 5 * 60 * 1000,
    });

    const environmentIdMap = React.useMemo(() => {
        const map: Record<string, number> = {};
        environments.forEach(e => { map[e.name] = e.id; });
        return map;
    }, [environments]);

    const { data, isLoading, error, refetch, isFetching } = useQuery({
        queryKey: queryKeys.secrets.list({
            ...filters, page: pagination.page, pageSize: pagination.pageSize, sortBy,
        }),
        queryFn: () => apiService.secrets.list({
            page: pagination.page,
            pageSize: pagination.pageSize,
            search: filters.search || undefined,
            type: filters.type !== 'all' ? filters.type : undefined,
            namespace: filters.namespace || undefined,
            zone: filters.zone || undefined,
            environment_id: filters.environment && environmentIdMap[filters.environment]
                ? environmentIdMap[filters.environment] : undefined,
            tags: filters.tags.length > 0 ? filters.tags : undefined,
        }),
        keepPreviousData: true,
    });

    React.useEffect(() => {
        if (data) setPagination(prev => ({ ...prev, total: data.total, totalPages: data.totalPages }));
    }, [data]);

    const secrets = useMemo(() => {
        if (!data?.data) return [];
        const result = [...data.data];
        const [sortField, sortDirection] = sortBy.split('_');
        result.sort((a, b) => {
            let aVal: any, bVal: any;
            if (sortField === 'name') { aVal = a.name.toLowerCase(); bVal = b.name.toLowerCase(); }
            else if (sortField === 'modified') { aVal = new Date(a.lastModified); bVal = new Date(b.lastModified); }
            else if (sortField === 'type') { aVal = a.type; bVal = b.type; }
            else return 0;
            if (aVal < bVal) return sortDirection === 'asc' ? -1 : 1;
            if (aVal > bVal) return sortDirection === 'asc' ? 1 : -1;
            return 0;
        });
        return result;
    }, [data?.data, sortBy]);

    const handleFilterChange = useCallback((key: keyof SecretFilters, value: any) => {
        setFilters(prev => ({ ...prev, [key]: value }));
        setPagination(prev => ({ ...prev, page: 1 }));
    }, []);

    React.useEffect(() => {
        const timer = setTimeout(() => handleFilterChange('search', searchInput), 300);
        return () => clearTimeout(timer);
    }, [searchInput, handleFilterChange]);

    const handleAddTag = useCallback((tag: string) => {
        if (tag.trim() && !filters.tags.includes(tag.trim()))
            handleFilterChange('tags', [...filters.tags, tag.trim()]);
        setTagInput('');
    }, [filters.tags, handleFilterChange]);

    const handleRemoveTag = useCallback((tagToRemove: string) => {
        handleFilterChange('tags', filters.tags.filter(t => t !== tagToRemove));
    }, [filters.tags, handleFilterChange]);

    const handleTagInputKeyPress = useCallback((e: React.KeyboardEvent) => {
        if (e.key === 'Enter' && tagInput.trim()) { e.preventDefault(); handleAddTag(tagInput); }
    }, [tagInput, handleAddTag]);

    const handlePageChange = useCallback((page: number) => setPagination(prev => ({ ...prev, page })), []);
    const handlePageSizeChange = useCallback((pageSize: number) =>
        setPagination(prev => ({ ...prev, pageSize, page: 1 })), []);

    const handleClearFilters = useCallback(() => {
        setFilters({ search: '', type: 'all', namespace: '', zone: '', environment: '', tags: [] });
        setSearchInput('');
        setTagInput('');
        setPagination(prev => ({ ...prev, page: 1 }));
    }, []);

    const hasActiveFilters = useMemo(() =>
        !!(filters.search || filters.type !== 'all' || filters.namespace || filters.zone ||
            filters.environment || filters.tags.length > 0), [filters]);

    // Mutations
    const createMutation = useMutation({
        mutationFn: (d: SecretFormData) => apiService.secrets.create(d),
        onSuccess: () => { closeModal(); refetch(); },
    });

    const editMutation = useMutation({
        mutationFn: ({ id, name, type, value }: { id: number; name: string; type: SecretType; value: string }) => {
            const updateData: Partial<SecretFormData> = { name, type };
            if (value.trim()) updateData.value = value;
            return apiService.secrets.update(id, updateData);
        },
        onSuccess: () => { closeModal(); refetch(); },
    });

    const deleteMutation = useMutation({
        mutationFn: (id: number) => apiService.secrets.delete(id),
        onSuccess: () => { closeModal(); refetch(); },
    });

    const rotateMutation = useMutation({
        mutationFn: ({ id, newValue }: { id: number; newValue: string }) => apiService.rotateSecret(id, newValue),
        onSuccess: () => { refetch(); },
    });

    const bulkDeleteMutation = useMutation({
        mutationFn: (ids: number[]) => Promise.all(ids.map(id => apiService.secrets.delete(id))),
        onSuccess: () => { closeModal(); clearSelectedItems(); setBulkActionMode(false); refetch(); },
    });

    return {
        secrets, data, isLoading, error, refetch, isFetching,
        filters, setFilters, pagination, setPagination, sortBy, setSortBy,
        tagInput, setTagInput, searchInput, setSearchInput,
        showAdvancedFilters, setShowAdvancedFilters,
        selectedItems, bulkActionMode, setBulkActionMode, toggleSelectedItem, clearSelectedItems,
        environments,
        handleFilterChange, handleAddTag, handleRemoveTag, handleTagInputKeyPress,
        handlePageChange, handlePageSizeChange, handleClearFilters, hasActiveFilters,
        createMutation, editMutation, deleteMutation, rotateMutation, bulkDeleteMutation,
        openModal, closeModal, activeModal, modalData,
    };
};
