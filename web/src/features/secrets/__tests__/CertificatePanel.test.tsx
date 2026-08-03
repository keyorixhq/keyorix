import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '../../../test/test-utils';
import { CertificatePanel } from '../CertificatePanel';

const mockUseCert = vi.fn();

vi.mock('../api', () => ({
    useSecretCertificate: (id: number) => mockUseCert(id),
}));

const baseCert = {
    secret_id: 7,
    secret_name: 'tls-cert',
    subject: 'CN=example.com',
    issuer: 'CN=Example CA',
    serial_number: '4242',
    not_before: '2025-06-23T00:00:00Z',
    not_after: '2026-09-21T00:00:00Z',
    days_until_expiry: 90,
    is_expired: false,
    is_ca: false,
    self_signed: false,
    dns_names: ['example.com', 'www.example.com'],
    signature_algorithm: 'ECDSA-SHA256',
    public_key_algorithm: 'ECDSA',
};

describe('CertificatePanel', () => {
    it('renders cert metadata with a valid badge and SANs', () => {
        mockUseCert.mockReturnValue({ data: baseCert, isLoading: false, isError: false });
        render(<CertificatePanel secretId={7} />);
        expect(screen.getByText('CN=example.com')).toBeInTheDocument();
        expect(screen.getByText('CN=Example CA')).toBeInTheDocument();
        expect(screen.getByText(/Valid · 90d left/)).toBeInTheDocument();
        expect(screen.getByText(/example.com, www.example.com/)).toBeInTheDocument();
    });

    it('shows an expired badge', () => {
        mockUseCert.mockReturnValue({
            data: { ...baseCert, is_expired: true, days_until_expiry: -5 },
            isLoading: false,
            isError: false,
        });
        render(<CertificatePanel secretId={7} />);
        expect(screen.getByText('Expired')).toBeInTheDocument();
    });

    it('shows an expiring-soon badge within 30 days', () => {
        mockUseCert.mockReturnValue({ data: { ...baseCert, days_until_expiry: 12 }, isLoading: false, isError: false });
        render(<CertificatePanel secretId={7} />);
        expect(screen.getByText('Expires in 12d')).toBeInTheDocument();
    });

    it('marks a self-signed certificate', () => {
        mockUseCert.mockReturnValue({ data: { ...baseCert, self_signed: true }, isLoading: false, isError: false });
        render(<CertificatePanel secretId={7} />);
        expect(screen.getByText('(self-signed)')).toBeInTheDocument();
    });

    it('renders nothing when the value is not a certificate (error)', () => {
        mockUseCert.mockReturnValue({ data: undefined, isLoading: false, isError: true });
        const { container } = render(<CertificatePanel secretId={7} />);
        expect(container).toBeEmptyDOMElement();
    });

    it('shows a loading skeleton while the certificate is being fetched', () => {
        mockUseCert.mockReturnValue({ data: undefined, isLoading: true, isError: false });
        const { container } = render(<CertificatePanel secretId={7} />);
        expect(container.querySelectorAll('.animate-pulse').length).toBeGreaterThan(0);
        expect(screen.queryByText('CN=example.com')).not.toBeInTheDocument();
    });

    it('marks a certificate authority', () => {
        mockUseCert.mockReturnValue({ data: { ...baseCert, is_ca: true }, isLoading: false, isError: false });
        render(<CertificatePanel secretId={7} />);
        expect(screen.getByText(/Certificate Authority/)).toBeInTheDocument();
    });

    it('falls back to the raw string when a validity date fails to parse', () => {
        mockUseCert.mockReturnValue({
            data: { ...baseCert, not_before: 'not-a-date' },
            isLoading: false,
            isError: false,
        });
        render(<CertificatePanel secretId={7} />);
        expect(screen.getByText(/not-a-date/)).toBeInTheDocument();
    });
});
