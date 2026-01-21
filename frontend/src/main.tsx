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
import { Dashboard } from './components/dashboard/Dashboard';
import AccessLogs from './components/AccessLogs';
import RBACManager from './components/rbac/RBACManager';
import OrganizationList from './components/rbac/OrganizationList';
import GroupList from './components/rbac/GroupList';
import RoleList from './components/rbac/RoleList';
import UserList from './components/rbac/UserList';
import ContractList from './components/rbac/ContractList';
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

                {/* Admin dashboard with nested routes */}
                <Route path="/admin" element={<AdminApp />}>
                  <Route index element={<Navigate to="dashboard" replace />} />
                  <Route path="dashboard" element={<Dashboard />} />
                  <Route path="logs" element={<AccessLogs />} />
                  <Route path="rbac" element={<RBACManager />}>
                    <Route index element={<Navigate to="organizations" replace />} />
                    <Route path="organizations" element={<OrganizationList />} />
                    <Route path="groups" element={<GroupList />} />
                    <Route path="roles" element={<RoleList />} />
                    <Route path="users" element={<UserList />} />
                    <Route path="users/:userId" element={<UserList />} />
                    <Route path="contracts" element={<ContractList />} />
                  </Route>
                </Route>

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
