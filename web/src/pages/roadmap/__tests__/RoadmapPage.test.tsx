import { describe, it, expect } from 'vitest';
import { render, screen, within } from '../../../test/test-utils';
import { RoadmapPage } from '../RoadmapPage';

describe('RoadmapPage', () => {
    it('renders the page heading and intro copy', () => {
        render(<RoadmapPage />);

        expect(screen.getByRole('heading', { level: 1, name: 'Roadmap' })).toBeInTheDocument();
        expect(screen.getByText("What's being built and when. Updated as priorities change.")).toBeInTheDocument();
    });

    it('renders all four quarter sections as level-2 headings, in order', () => {
        render(<RoadmapPage />);

        const headings = screen.getAllByRole('heading', { level: 2 });
        expect(headings.map((h) => h.textContent)).toEqual(['Now — v0.1.0', 'Q3 2026', 'Q4 2026', '2027']);
    });

    it('labels each quarter card with its status badge', () => {
        render(<RoadmapPage />);

        const nowCard = screen.getByRole('heading', { level: 2, name: 'Now — v0.1.0' }).closest('div')
            ?.parentElement as HTMLElement;
        expect(within(nowCard).getByText('Shipped')).toBeInTheDocument();

        const q3Card = screen.getByRole('heading', { level: 2, name: 'Q3 2026' }).closest('div')
            ?.parentElement as HTMLElement;
        expect(within(q3Card).getByText('Shipped')).toBeInTheDocument();

        const q4Card = screen.getByRole('heading', { level: 2, name: 'Q4 2026' }).closest('div')
            ?.parentElement as HTMLElement;
        expect(within(q4Card).getByText('Planned')).toBeInTheDocument();

        const futureCard = screen.getByRole('heading', { level: 2, name: '2027' }).closest('div')
            ?.parentElement as HTMLElement;
        expect(within(futureCard).getByText('Roadmap')).toBeInTheDocument();
    });

    it('renders every roadmap item for the "Now" quarter', () => {
        render(<RoadmapPage />);

        expect(screen.getByText('Secret CRUD, versioning, and rotation')).toBeInTheDocument();
        expect(screen.getByText('AES-256-GCM envelope encryption with key rotation')).toBeInTheDocument();
        expect(screen.getByText('Full RBAC — users, groups, roles, permissions')).toBeInTheDocument();
        expect(screen.getByText('Secrets Health dashboard')).toBeInTheDocument();
        expect(screen.getByText('Docker Compose with auto-seeding')).toBeInTheDocument();
        expect(screen.getByText('NIS2, DORA, ISO 27001 compliance page')).toBeInTheDocument();
    });

    it('renders every roadmap item for the Q3 2026 quarter', () => {
        render(<RoadmapPage />);

        expect(screen.getByText('Project-scoped role assignments')).toBeInTheDocument();
        expect(screen.getByText('RBAC audit log UI with actor / date filters and CSV export')).toBeInTheDocument();
        expect(screen.getByText('Role creation and management UI')).toBeInTheDocument();
        expect(
            screen.getByText(
                'Compliance mapping reports (NIS2, DORA, ISO 27001, SOC 2, DORA, ENS) with per-framework scores'
            )
        ).toBeInTheDocument();
        expect(
            screen.getByText('OIDC service account authentication UI for CI/CD (backend in Q4)')
        ).toBeInTheDocument();
        expect(screen.getByText('Project switcher in sidebar header')).toBeInTheDocument();
        expect(
            screen.getByText('Effective permissions panel and role legend in project Members tab')
        ).toBeInTheDocument();
        expect(screen.getByText('Dynamic secrets (database credentials, cloud keys)')).toBeInTheDocument();
        expect(screen.getByText('User invitation and access request flows')).toBeInTheDocument();
        expect(screen.getByText('Webhook notifications for rotation events')).toBeInTheDocument();
        expect(screen.getByText('Real-time self-hosted install health status')).toBeInTheDocument();
    });

    it('renders every roadmap item for the Q4 2026 quarter', () => {
        render(<RoadmapPage />);

        expect(screen.getByText('Kubernetes operator (alpha)')).toBeInTheDocument();
        expect(screen.getByText('OIDC federation backend (token exchange endpoint)')).toBeInTheDocument();
        expect(screen.getByText('demo.keyorix.com hosted demo environment')).toBeInTheDocument();
    });

    it('renders every roadmap item for the 2027 quarter', () => {
        render(<RoadmapPage />);

        expect(screen.getByText('Keyorix Connect federation UI')).toBeInTheDocument();
        expect(screen.getByText('Cross-environment drift detection')).toBeInTheDocument();
        expect(screen.getByText('ML-based anomaly detection')).toBeInTheDocument();
        expect(screen.getByText('gRPC client library')).toBeInTheDocument();
        expect(screen.getByText('Multi-region replication')).toBeInTheDocument();
    });

    it('renders the footer disclaimer', () => {
        render(<RoadmapPage />);

        expect(
            screen.getByText(
                'Roadmap reflects current intentions and may change. Enterprise features require a commercial licence.'
            )
        ).toBeInTheDocument();
    });
});
