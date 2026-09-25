// Self-test for the xss-payloads harness (src/test/xss-payloads.ts): proves
// assertPayloadRenderedSafely actually distinguishes safe rendering from an
// unsafe sink, rather than passing regardless of what it's pointed at. A
// helper that can't fail on a known-bad case would give every real call
// site a false "safe" result.
import { describe, it, expect, afterEach } from 'vitest';
import { render, cleanup } from '../test-utils';
import { XSS_PAYLOADS, assertPayloadRenderedSafely } from '../xss-payloads';

afterEach(() => {
    cleanup();
});

const SafeText: React.FC<{ value: string }> = ({ value }) => <div>{value}</div>;

// Deliberately vulnerable — exists only to prove the harness catches this
// shape. Never do this in real component code (see the WEB track backlog:
// no dangerouslySetInnerHTML/innerHTML for user-controlled fields).
const UnsafeHtml: React.FC<{ value: string }> = ({ value }) => <div dangerouslySetInnerHTML={{ __html: value }} />;

describe('xss-payloads harness self-test', () => {
    it('passes every payload against safe (plain JSX text) rendering', () => {
        for (const payload of XSS_PAYLOADS) {
            const { container, unmount } = render(<SafeText value={payload} />);
            expect(() => assertPayloadRenderedSafely(payload, container)).not.toThrow();
            unmount();
        }
    });

    it('fails the img-onerror payload against an unsafe dangerouslySetInnerHTML sink', () => {
        const payload = '<img src=x onerror="window.__xssFired=true">';
        const { container } = render(<UnsafeHtml value={payload} />);
        // The unsafe sink actually created a live <img onerror> element —
        // structural proof of the gap. jsdom never performs a real image
        // load, so the onerror handler itself does not fire here the way it
        // would in a real browser; the element's presence is what this
        // harness checks, not the handler firing (see xss-payloads.ts's own
        // comment on this).
        expect(container.querySelector('img[onerror]')).toBeInTheDocument();
        expect(() => assertPayloadRenderedSafely(payload, container)).toThrow();
    });

    it('fails the script-tag payload against an unsafe dangerouslySetInnerHTML sink', () => {
        const payload = '<script>window.__xssFired=true</script>';
        const { container } = render(<UnsafeHtml value={payload} />);
        // Browsers (and jsdom, matching that behavior) never execute a
        // <script> inserted via innerHTML, but it IS still parsed into a
        // real (inert) <script> element — still a structural difference
        // from safe text rendering, and still what this harness must catch.
        expect(container.querySelector('script')).toBeInTheDocument();
        expect(() => assertPayloadRenderedSafely(payload, container)).toThrow();
    });
});
