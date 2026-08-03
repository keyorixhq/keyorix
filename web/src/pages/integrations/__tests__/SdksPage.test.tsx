import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '../../../test/test-utils';
import { SdksPage } from '../SdksPage';

describe('SdksPage', () => {
    it('renders the page heading and intro copy', () => {
        render(<SdksPage />);
        expect(screen.getByRole('heading', { level: 1, name: 'SDKs & CLI' })).toBeInTheDocument();
    });

    it('renders the CLI install and connect commands', () => {
        render(<SdksPage />);
        expect(
            screen.getByText('curl -L https://raw.githubusercontent.com/keyorixhq/keyorix/main/install.sh | sh')
        ).toBeInTheDocument();
        expect(
            screen.getByText('keyorix connect http://your-server:8080 --username admin --password yourpassword')
        ).toBeInTheDocument();
    });

    it('links the Personal Access Token callout to the Profile page', () => {
        render(<SdksPage />);
        expect(screen.getByRole('link', { name: 'Personal Access Token' })).toHaveAttribute('href', '/profile');
    });

    it('renders install commands and usage snippets for Go, Python, and Node.js', () => {
        render(<SdksPage />);
        expect(screen.getByText('go get github.com/keyorixhq/keyorix-go')).toBeInTheDocument();
        expect(screen.getByText('pip install keyorix')).toBeInTheDocument();
        expect(screen.getByText('npm install keyorix')).toBeInTheDocument();
        expect(screen.getByText(/client\.GetSecret/)).toBeInTheDocument();
        expect(screen.getByText(/client\.get_secret/)).toBeInTheDocument();
        expect(screen.getByText(/client\.getSecret/)).toBeInTheDocument();
    });

    it('links to the live Swagger/OpenAPI reference', () => {
        render(<SdksPage />);
        const link = screen.getByRole('link', { name: '/swagger' });
        expect(link).toHaveAttribute('href', '/swagger');
        expect(link).toHaveAttribute('target', '_blank');
    });

    it('copies a code block to the clipboard when its copy button is clicked', async () => {
        const writeText = vi.fn().mockResolvedValue(undefined);
        Object.assign(navigator, { clipboard: { writeText } });

        render(<SdksPage />);
        const copyButtons = screen.getAllByRole('button', { name: 'Copy to clipboard' });
        fireEvent.click(copyButtons[0]!);

        await waitFor(() => expect(writeText).toHaveBeenCalled());
    });
});
