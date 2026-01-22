import { createContext, useContext, useState, useEffect, ReactNode, useCallback } from 'react';

interface AuthState {
  isAuthenticated: boolean;
  accessToken: string | null;
  refreshToken: string | null;
  userDID: string | null;
  expiresAt: number | null;
}

interface AuthContextType extends AuthState {
  login: (accessToken: string, refreshToken: string, expiresIn: number) => void;
  logout: () => void;
  refreshAccessToken: () => Promise<boolean>;
  isLoading: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

const STORAGE_KEY = 'privacy_proxy_auth';

interface StoredAuth {
  accessToken: string;
  refreshToken: string;
  expiresAt: number;
}

function parseJWT(token: string): { sub?: string; exp?: number } | null {
  try {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(
      atob(base64)
        .split('')
        .map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
        .join('')
    );
    return JSON.parse(jsonPayload);
  } catch {
    return null;
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>({
    isAuthenticated: false,
    accessToken: null,
    refreshToken: null,
    userDID: null,
    expiresAt: null,
  });
  const [isLoading, setIsLoading] = useState(true);

  // Load auth state from localStorage on mount
  useEffect(() => {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored) {
      try {
        const auth: StoredAuth = JSON.parse(stored);
        const now = Date.now();

        // Check if token is still valid (with 1 minute buffer)
        if (auth.expiresAt > now + 60000) {
          const claims = parseJWT(auth.accessToken);
          setState({
            isAuthenticated: true,
            accessToken: auth.accessToken,
            refreshToken: auth.refreshToken,
            userDID: claims?.sub || null,
            expiresAt: auth.expiresAt,
          });
        } else if (auth.refreshToken) {
          // Token expired but we have refresh token - try to refresh
          refreshWithToken(auth.refreshToken);
        } else {
          localStorage.removeItem(STORAGE_KEY);
        }
      } catch {
        localStorage.removeItem(STORAGE_KEY);
      }
    }
    setIsLoading(false);
  }, []);

  const refreshWithToken = async (refreshToken: string): Promise<boolean> => {
    try {
      const response = await fetch('/api/v1/refresh', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: refreshToken }),
      });

      if (!response.ok) {
        throw new Error('Refresh failed');
      }

      const data = await response.json();
      const expiresAt = Date.now() + data.expires_in * 1000;
      const claims = parseJWT(data.access_token);

      const newAuth: StoredAuth = {
        accessToken: data.access_token,
        refreshToken: data.refresh_token,
        expiresAt,
      };
      localStorage.setItem(STORAGE_KEY, JSON.stringify(newAuth));

      setState({
        isAuthenticated: true,
        accessToken: data.access_token,
        refreshToken: data.refresh_token,
        userDID: claims?.sub || null,
        expiresAt,
      });

      return true;
    } catch {
      localStorage.removeItem(STORAGE_KEY);
      setState({
        isAuthenticated: false,
        accessToken: null,
        refreshToken: null,
        userDID: null,
        expiresAt: null,
      });
      return false;
    }
  };

  const login = useCallback((accessToken: string, refreshToken: string, expiresIn: number) => {
    const expiresAt = Date.now() + expiresIn * 1000;
    const claims = parseJWT(accessToken);

    const auth: StoredAuth = {
      accessToken,
      refreshToken,
      expiresAt,
    };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(auth));

    setState({
      isAuthenticated: true,
      accessToken,
      refreshToken,
      userDID: claims?.sub || null,
      expiresAt,
    });
  }, []);

  const logout = useCallback(async () => {
    // Revoke both tokens on server for immediate invalidation
    // Access token revocation ensures immediate logout (vs 30 min expiry)
    if (state.refreshToken) {
      try {
        await fetch('/api/v1/revoke', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            refresh_token: state.refreshToken,
            access_token: state.accessToken, // Include for immediate invalidation
          }),
        });
      } catch {
        // Ignore errors, we're logging out anyway
      }
    }

    localStorage.removeItem(STORAGE_KEY);
    setState({
      isAuthenticated: false,
      accessToken: null,
      refreshToken: null,
      userDID: null,
      expiresAt: null,
    });
  }, [state.refreshToken, state.accessToken]);

  const refreshAccessToken = useCallback(async (): Promise<boolean> => {
    if (!state.refreshToken) return false;
    return refreshWithToken(state.refreshToken);
  }, [state.refreshToken]);

  // Auto-refresh token before expiry
  useEffect(() => {
    if (!state.expiresAt || !state.refreshToken) return;

    const timeUntilExpiry = state.expiresAt - Date.now();
    const refreshTime = timeUntilExpiry - 60000; // Refresh 1 minute before expiry

    if (refreshTime <= 0) {
      refreshAccessToken();
      return;
    }

    const timer = setTimeout(() => {
      refreshAccessToken();
    }, refreshTime);

    return () => clearTimeout(timer);
  }, [state.expiresAt, state.refreshToken, refreshAccessToken]);

  return (
    <AuthContext.Provider
      value={{
        ...state,
        login,
        logout,
        refreshAccessToken,
        isLoading,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
