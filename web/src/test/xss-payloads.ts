// Shared XSS regression payloads for user-controlled string fields (secret
// names/descriptions, project names/descriptions, audit event descriptions).
// WEB track backlog item 3: every render site for these fields must prove
// the payload is displayed as inert text, never executed or parsed as
// markup. React's JSX text-child escaping is structural, but that is a
// property of the rendering library, not of any single component -- these
// tests exist to catch a future dangerouslySetInnerHTML/innerHTML
// regression at the actual render sites, not to re-prove React's own
// behavior in the abstract.
//
// assertPayloadRenderedSafely is the one shared assertion every call site
// below uses: the payload's exact text is present in the DOM (so it was not
// silently stripped/mangled), and no live element was created FROM the
// payload's markup (an injected <img>/<script> would appear as a real
// element with that tag name if the sink were unsafe; under safe text
// rendering it only ever appears as escaped text inside the container).
//
// This deliberately does NOT assert an onerror/onload handler actually
// FIRED: jsdom (this suite's DOM) never performs real image loads, so a
// broken <img src=x onerror=...> inserted via an unsafe sink never fires
// its handler here the way it would in a real browser (confirmed against
// this exact harness -- see xss-payloads.selftest.test.tsx). The element's
// mere presence in the DOM, from a sink that should only ever produce text,
// is itself the structural proof of the gap; waiting for a jsdom event that
// will never come would make this check vacuously pass on real vulnerable
// code.
import { screen } from '@testing-library/react';
import { expect } from 'vitest';

export const XSS_PAYLOADS: readonly string[] = [
    // Classic reflected-DOM XSS via an error-handler attribute.
    '<img src=x onerror="window.__xssFired=true">',
    // javascript: URL scheme -- relevant if a name/description is ever used
    // as an href rather than plain text.
    '<a href="javascript:window.__xssFired=true">click</a>',
    // A bare <script> tag -- the most basic sink-detection payload.
    '<script>window.__xssFired=true</script>',
    // RTL override (U+202E) plus zero-width characters -- not code execution,
    // but a visual-spoofing trick (e.g. making "evil.exe" display reversed,
    // or hiding characters) that a naive display layer could still be fooled
    // by if it tried to interpret rather than just display the string.
    '‮evil​‌name',
] as const;

export function assertPayloadRenderedSafely(payload: string, container: HTMLElement = document.body): void {
    // The literal text must be present verbatim — proves it wasn't stripped
    // (which would hide a real gap behind a false "safe" result) or decoded
    // into live markup (which would make the literal string absent, replaced
    // by the elements it described).
    expect(screen.getByText(payload, { exact: false })).toBeInTheDocument();

    // No element was actually created from the payload's markup.
    expect(container.querySelector('img[onerror]')).not.toBeInTheDocument();
    expect(container.querySelector('script')).not.toBeInTheDocument();
    expect(container.querySelector('a[href^="javascript:"]')).not.toBeInTheDocument();
}
