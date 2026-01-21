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
        // Allow any host for Tailscale and local network access
        allowedHosts: ['localhost', 'max-mac', '127.0.0.1', '.local', 'proxy-frontend'],
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
        },
    },
});
