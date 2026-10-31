import React from 'react';
import qrcode from 'qrcode-generator';

const QUIET_ZONE = 4; // modules; the QR spec's minimum

// qrPath encodes `text` and returns the SVG path of its dark modules plus the side length in
// modules (quiet zone included). Encoding is local: no network request, so the air-gapped
// deployment story holds. Returns null when the text cannot be encoded.
export function qrPath(text: string): { d: string; size: number } | null {
    try {
        const qr = qrcode(0, 'M'); // type 0 = smallest version that fits
        qr.addData(text);
        qr.make();
        const n = qr.getModuleCount();
        let d = '';
        for (let r = 0; r < n; r++) {
            for (let c = 0; c < n; c++) {
                if (qr.isDark(r, c)) d += `M${c + QUIET_ZONE} ${r + QUIET_ZONE}h1v1h-1z`;
            }
        }
        return { d, size: n + QUIET_ZONE * 2 };
    } catch {
        return null;
    }
}

// QrCode renders `value` as an SVG QR code. Always black on white regardless of theme:
// scanners need the contrast. Renders nothing if the value cannot be encoded, so callers keep
// a text fallback next to it.
export const QrCode: React.FC<{ value: string; label?: string; size?: number }> = ({
    value,
    label = 'QR code',
    size = 176,
}) => {
    const qr = React.useMemo(() => qrPath(value), [value]);
    if (!qr) return null;
    return (
        <svg
            data-testid="qr-code"
            role="img"
            aria-label={label}
            viewBox={`0 0 ${qr.size} ${qr.size}`}
            width={size}
            height={size}
            shapeRendering="crispEdges"
            className="rounded-md"
        >
            <rect width={qr.size} height={qr.size} fill="#ffffff" />
            <path d={qr.d} fill="#000000" />
        </svg>
    );
};
