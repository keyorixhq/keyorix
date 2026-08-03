import { describe, it, expect } from 'vitest';
import { CLASSIFICATION_LEVELS, CLASSIFICATION_META, UNCLASSIFIED_META, classificationMeta } from '../classification';

describe('classificationMeta', () => {
    it('returns the matching meta for each known classification level', () => {
        expect(classificationMeta('public')).toBe(CLASSIFICATION_META.public);
        expect(classificationMeta('internal')).toBe(CLASSIFICATION_META.internal);
        expect(classificationMeta('confidential')).toBe(CLASSIFICATION_META.confidential);
        expect(classificationMeta('restricted')).toBe(CLASSIFICATION_META.restricted);
    });

    it('returns the unclassified meta for an empty level', () => {
        expect(classificationMeta('')).toBe(UNCLASSIFIED_META);
    });

    it('falls back to the unclassified meta for an unrecognized level', () => {
        expect(classificationMeta('not-a-real-level')).toBe(UNCLASSIFIED_META);
    });

    it('exposes the selectable levels, unclassified first', () => {
        expect(CLASSIFICATION_LEVELS[0]).toBe('');
        expect(CLASSIFICATION_LEVELS).toEqual(['', 'public', 'internal', 'confidential', 'restricted']);
    });
});
