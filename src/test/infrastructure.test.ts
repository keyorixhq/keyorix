import { describe, it, expect, vi } from 'vitest';
import { mockUser, mockSecrets, setupMocks } from './mocks';
import { formHelpers } from './form-helpers';

describe('Testing Infrastructure', () => {
    it('should provide mock data', () => {
        expect(mockUser).toBeDefined();
        expect(mockUser.username).toBe('testuser');
        expect(mockSecrets).toHaveLength(3);
        expect(mockSecrets[0]?.name).toBe('database-password');
    });

    it('should setup mocks correctly', () => {
        setupMocks();

        // Test localStorage mock
        localStorage.setItem('test', 'value');
        expect(localStorage.setItem).toHaveBeenCalledWith('test', 'value');

        // Test clipboard mock
        navigator.clipboard.writeText('test');
        expect(navigator.clipboard.writeText).toHaveBeenCalledWith('test');
    });

    it('should provide form helpers', () => {
        expect(formHelpers).toBeDefined();
        expect(typeof formHelpers.fillInput).toBe('function');
        expect(typeof formHelpers.submitForm).toBe('function');
    });

    it('should handle vitest mocking', () => {
        const mockFn = vi.fn();
        mockFn('test');

        expect(mockFn).toHaveBeenCalledWith('test');
        expect(mockFn).toHaveBeenCalledTimes(1);
    });
});