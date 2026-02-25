import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';
function isThirdPartyPureAnnotationWarning(warning) {
    var _a;
    if (warning.code !== 'INVALID_ANNOTATION')
        return false;
    if (!((_a = warning.message) === null || _a === void 0 ? void 0 : _a.includes('contains an annotation that Rollup cannot interpret')))
        return false;
    var id = 'id' in warning ? warning.id : undefined;
    return typeof id === 'string' && id.includes('/node_modules/');
}
// https://vitejs.dev/config/
export default defineConfig({
    plugins: [react()],
    build: {
        // Wallet SDK dependencies are intentionally large; this threshold avoids
        // noisy warnings while still surfacing genuinely abnormal growth.
        chunkSizeWarningLimit: 2000,
        rollupOptions: {
            onwarn: function (warning, warn) {
                if (isThirdPartyPureAnnotationWarning(warning))
                    return;
                warn(warning);
            },
        },
    },
    resolve: {
        alias: {
            "@": path.resolve(__dirname, "./src"),
        },
    },
    server: {
        port: 5173,
        host: '0.0.0.0',
        // Allow all hosts in development for ngrok/external access
        allowedHosts: true,
        proxy: {
            '/api': {
                // Default to localhost:8080 for local development
                // Docker sets VITE_API_TARGET=http://proxy-backend:8080
                // For Tailscale/remote access, create .env.local with:
                //   VITE_API_TARGET=http://your-hostname:8080
                target: process.env.VITE_API_TARGET || 'http://localhost:8080',
                changeOrigin: true,
                configure: function (proxy) {
                    proxy.on('proxyReq', function (proxyReq, req) {
                        // Forward original host so backend can build correct callback URLs
                        var originalHost = req.headers.host;
                        if (originalHost) {
                            proxyReq.setHeader('X-Forwarded-Host', originalHost);
                            proxyReq.setHeader('X-Forwarded-Proto', 'http');
                        }
                    });
                },
            },
            // Proxy JSON-RPC requests to backend
            '/rpc': {
                target: process.env.VITE_API_TARGET || 'http://localhost:8080',
                changeOrigin: true,
            },
        },
    },
});
