// Shared data-classification presentation (ISO 27001 A.5.12). Used by the secret
// detail view, the secrets-list row badge, and the list/filter controls so the
// labels, ordering, and colours stay consistent.

export const UNCLASSIFIED_META = {
    label: 'Unclassified',
    color: 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300',
};

export const CLASSIFICATION_META: Record<string, { label: string; color: string }> = {
    '': UNCLASSIFIED_META,
    public: { label: 'Public', color: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200' },
    internal: { label: 'Internal', color: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200' },
    confidential: {
        label: 'Confidential',
        color: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200',
    },
    restricted: { label: 'Restricted', color: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200' },
};

// Selectable levels, unclassified first (matches the detail-view picker order).
export const CLASSIFICATION_LEVELS = ['', 'public', 'internal', 'confidential', 'restricted'];

export const classificationMeta = (level: string) => CLASSIFICATION_META[level] ?? UNCLASSIFIED_META;
