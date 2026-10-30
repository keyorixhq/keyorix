import { describe, it, expect } from 'vitest';
import qrcode from 'qrcode-generator';
import { render, screen } from '../../../test/test-utils';
import { QrCode, qrPath } from '../QrCode';

const URI = 'otpauth://totp/Keyorix:alice?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Keyorix';

describe('QrCode', () => {
    it('renders an SVG with dark modules for a known otpauth URI', () => {
        render(<QrCode value={URI} label="scan me" />);
        const svg = screen.getByRole('img', { name: 'scan me' });
        expect(svg.tagName.toLowerCase()).toBe('svg');
        expect(svg.querySelector('path')?.getAttribute('d')).toMatch(/^M\d+ \d+h1v1h-1z/);
    });

    it('encodes exactly the matrix the encoder produces for the URI (quiet zone of 4)', () => {
        const ref = qrcode(0, 'M');
        ref.addData(URI);
        ref.make();
        const n = ref.getModuleCount();
        const out = qrPath(URI);
        expect(out?.size).toBe(n + 8);
        let dark = 0;
        for (let r = 0; r < n; r++) for (let c = 0; c < n; c++) if (ref.isDark(r, c)) dark++;
        expect(out?.d.split('M').length - 1).toBe(dark);
    });

    it('makes no network request while rendering', () => {
        const calls: unknown[] = [];
        const orig = globalThis.fetch;
        globalThis.fetch = ((...a: unknown[]) => {
            calls.push(a);
            return Promise.reject(new Error('no network'));
        }) as typeof fetch;
        try {
            render(<QrCode value={URI} />);
        } finally {
            globalThis.fetch = orig;
        }
        expect(calls).toHaveLength(0);
    });

    it('renders nothing when the value cannot be encoded', () => {
        const { container } = render(<QrCode value={'x'.repeat(5000)} />);
        expect(container.querySelector('svg')).toBeNull();
    });
});
