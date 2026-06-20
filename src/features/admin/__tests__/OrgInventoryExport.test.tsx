import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '../../../test/test-utils';
import { OrgInventoryExport } from '../OrgInventoryExport';

const mockGet = vi.fn();
vi.mock('../../../services/client', () => ({
    apiClient: { get: (...args: any[]) => mockGet(...args) },
}));

beforeEach(() => {
    mockGet.mockReset();
    (URL as any).createObjectURL = vi.fn(() => 'blob:mock');
    (URL as any).revokeObjectURL = vi.fn();
});

describe('OrgInventoryExport', () => {
    it('fetches the org inventory CSV as a blob on click', async () => {
        mockGet.mockResolvedValue({ data: new Blob(['project,id\n'], { type: 'text/csv' }) });

        render(<OrgInventoryExport />);
        fireEvent.click(screen.getByRole('button', { name: /export inventory/i }));

        await waitFor(() =>
            expect(mockGet).toHaveBeenCalledWith('/api/v1/secrets/inventory.csv', { responseType: 'blob' })
        );
        expect((URL as any).createObjectURL).toHaveBeenCalled();
    });

    it('surfaces an error when the export fails (e.g. 403)', async () => {
        mockGet.mockRejectedValue({ response: { data: { error: 'forbidden' } } });

        render(<OrgInventoryExport />);
        fireEvent.click(screen.getByRole('button', { name: /export inventory/i }));

        expect(await screen.findByText(/forbidden/i)).toBeInTheDocument();
    });
});
