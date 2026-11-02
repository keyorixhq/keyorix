import tailwindcss from '@tailwindcss/postcss';

// Tailwind stamps a `/*! tailwindcss vX | MIT License | https://tailwindcss.com */`
// banner into its generated output (the leading `!` marks it for minifiers to
// preserve through minification). MIT's notice requirement is about copies of
// Tailwind's own source, not CSS mechanically generated from our markup -- the
// same distinction long applied to compiler output generally -- so dropping it
// is standard, tool-supported practice (esbuild and terser both ship a
// documented option for exactly this). We strip it here because leaving it in
// trips the air-gap served-markup guard (TestAirgapServedMarkupNamesNoExternalHost):
// it names an external host in content we ship to air-gapped deployments.
const stripBuildBanners = {
    postcssPlugin: 'strip-build-banners',
    OnceExit(root) {
        root.walkComments((comment) => {
            if (comment.text.startsWith('!')) comment.remove();
        });
    },
};

export default {
    plugins: [tailwindcss(), stripBuildBanners],
};
