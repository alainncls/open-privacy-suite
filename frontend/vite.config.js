import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';
// https://vitejs.dev/config/
export default defineConfig({
    plugins: [react()],
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
            '/rpc': {
                // JSON-RPC endpoint proxy - rewrites /rpc to / on backend
                target: process.env.VITE_API_TARGET || 'http://localhost:8080',
                changeOrigin: true,
                rewrite: function (path) { return path.replace(/^\/rpc/, '/'); },
            },
        },
    },
});
