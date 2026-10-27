// Starts the vendored Swagger UI. A separate file, not an inline <script>, because
// the server's Content-Security-Policy is script-src 'self' (no 'unsafe-inline').
window.onload = function () {
    SwaggerUIBundle({
        url: '/openapi.yaml',
        dom_id: '#swagger-ui',
        deepLinking: true,
        // The default is the public online validator (validator.swagger.io), which the
        // page would call from the operator's browser. Off: no external request.
        validatorUrl: null,
        presets: [
            SwaggerUIBundle.presets.apis,
            SwaggerUIStandalonePreset
        ],
        plugins: [
            SwaggerUIBundle.plugins.DownloadUrl
        ],
        layout: "StandaloneLayout"
    });
};
