import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { WagmiProvider } from 'wagmi';
import { RainbowKitProvider, darkTheme } from '@rainbow-me/rainbowkit';
import '@rainbow-me/rainbowkit/styles.css';

import { wagmiConfig } from './config/wagmi';
import { AuthProvider } from './contexts/AuthContext';
import { LoginPage } from './pages/LoginPage';
import { LinkWalletPage } from './pages/LinkWalletPage';
import { SuccessPage } from './pages/SuccessPage';
import AdminApp from './App';
import './index.css';

const queryClient = new QueryClient();

// Custom RainbowKit theme to match our glass-morphism design
const customTheme = darkTheme({
  accentColor: '#6366f1',
  accentColorForeground: 'white',
  borderRadius: 'large',
  fontStack: 'system',
  overlayBlur: 'small',
});

function Root() {
  return (
    <WagmiProvider config={wagmiConfig}>
      <QueryClientProvider client={queryClient}>
        <RainbowKitProvider theme={customTheme} modalSize="compact">
          <AuthProvider>
            <BrowserRouter>
              <Routes>
                {/* Auth flow routes */}
                <Route path="/login" element={<LoginPage />} />
                <Route path="/link-wallet" element={<LinkWalletPage />} />
                <Route path="/success" element={<SuccessPage />} />

                {/* Admin dashboard */}
                <Route path="/admin/*" element={<AdminApp />} />

                {/* Default redirect to login */}
                <Route path="/" element={<Navigate to="/login" replace />} />

                {/* Catch all - redirect to login */}
                <Route path="*" element={<Navigate to="/login" replace />} />
              </Routes>
            </BrowserRouter>
          </AuthProvider>
        </RainbowKitProvider>
      </QueryClientProvider>
    </WagmiProvider>
  );
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <Root />
  </React.StrictMode>,
);
