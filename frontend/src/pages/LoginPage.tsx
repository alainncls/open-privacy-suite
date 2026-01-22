import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { QRCodeSVG } from 'qrcode.react';
import { Shield, Smartphone, ExternalLink, Loader2, AlertCircle, CheckCircle2, FlaskConical } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { useAuth } from '@/contexts/AuthContext';
import { authApiMethods, generatePrivadoLink, isMobileDevice, AuthRequestResponse, HumanityVerificationError } from '@/api/auth';

// Mock login requires explicit opt-in via VITE_ALLOW_MOCK_LOGIN=true
const allowMockLogin = import.meta.env.VITE_ALLOW_MOCK_LOGIN === 'true';

type AuthStep = 'init' | 'loading' | 'ready' | 'polling' | 'success' | 'error' | 'humanity_required';

interface AuthState {
  step: AuthStep;
  sessionId: string | null;
  authRequest: AuthRequestResponse['auth_request'] | null;
  error: string | null;
  humanityVerifyUrl: string | null;
}

export function LoginPage() {
  const navigate = useNavigate();
  const { login, isAuthenticated } = useAuth();
  const [state, setState] = useState<AuthState>({
    step: 'init',
    sessionId: null,
    authRequest: null,
    error: null,
    humanityVerifyUrl: null,
  });

  // Redirect if already authenticated
  useEffect(() => {
    if (isAuthenticated) {
      navigate('/link-wallet');
    }
  }, [isAuthenticated, navigate]);

  // Start auth request
  const startAuth = useCallback(async () => {
    setState(prev => ({ ...prev, step: 'loading', error: null }));

    try {
      const response = await authApiMethods.requestAuth();
      setState({
        step: 'ready',
        sessionId: response.session_id,
        authRequest: response.auth_request,
        error: null,
        humanityVerifyUrl: null,
      });
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to start authentication';
      setState(prev => ({ ...prev, step: 'error', error: errorMessage }));
    }
  }, []);

  // Mock login for development (requires explicit opt-in)
  const handleMockLogin = useCallback(async () => {
    if (!allowMockLogin) return;

    setState(prev => ({ ...prev, step: 'loading', error: null }));

    try {
      // Step 1: Get a session
      const authResponse = await authApiMethods.requestAuth();

      // Step 2: Verify with mock token (only works in dev mode on backend)
      const mockDID = `did:privado:dev_${Date.now()}`;
      const tokens = await authApiMethods.verifyAuth(authResponse.session_id, `mock.${mockDID}`);

      // Step 3: Login
      login(tokens.access_token, tokens.refresh_token, tokens.expires_in);
      setState(prev => ({ ...prev, step: 'success' }));
      setTimeout(() => navigate('/link-wallet'), 1000);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Mock login failed';
      setState(prev => ({ ...prev, step: 'error', error: errorMessage }));
    }
  }, [login, navigate]);

  // Auto-start on mount
  useEffect(() => {
    if (state.step === 'init') {
      startAuth();
    }
  }, [state.step, startAuth]);

  // Poll for session completion
  useEffect(() => {
    if (state.step !== 'ready' || !state.sessionId) return;

    let mounted = true;
    const pollInterval = 2000; // Poll every 2 seconds
    const maxPolls = 150; // 5 minutes max
    let pollCount = 0;

    const poll = async () => {
      if (!mounted || pollCount >= maxPolls) return;

      try {
        const result = await authApiMethods.pollSession(state.sessionId!);
        if (result && mounted) {
          login(result.access_token, result.refresh_token, result.expires_in);
          setState(prev => ({ ...prev, step: 'success' }));
          setTimeout(() => navigate('/link-wallet'), 1000);
          return;
        }
      } catch (err) {
        // Check for humanity verification error
        const errorData = err as { response?: { data?: HumanityVerificationError } };
        if (errorData?.response?.data?.error === 'humanity_verification_required') {
          setState(prev => ({
            ...prev,
            step: 'humanity_required',
            humanityVerifyUrl: errorData.response!.data!.verify_url,
          }));
          return;
        }
        // Otherwise continue polling
      }

      pollCount++;
      if (mounted && pollCount < maxPolls) {
        setTimeout(poll, pollInterval);
      }
    };

    // Start polling after a short delay
    const timer = setTimeout(poll, pollInterval);
    return () => {
      mounted = false;
      clearTimeout(timer);
    };
  }, [state.step, state.sessionId, login, navigate]);

  // Handle mobile deep link
  const handleMobileAuth = () => {
    if (!state.authRequest) return;
    const deepLink = generatePrivadoLink(state.authRequest);
    window.location.href = deepLink;
  };

  // Render QR code section
  const renderQRSection = () => {
    if (!state.authRequest) return null;

    const deepLink = generatePrivadoLink(state.authRequest);
    const isMobile = isMobileDevice();

    return (
      <div className="space-y-6" data-testid="qr-section">
        {/* QR Code for desktop */}
        {!isMobile && (
          <div className="flex flex-col items-center gap-4">
            <div className="p-4 bg-white rounded-2xl shadow-lg" role="img" aria-label="QR code for Privado ID authentication" data-testid="qr-code">
              <QRCodeSVG
                value={deepLink}
                size={200}
                level="M"
                includeMargin={false}
                aria-hidden="true"
              />
            </div>
            <p className="text-sm text-white/80 text-center">
              Scan with your Privado ID wallet
            </p>
          </div>
        )}

        {/* Mobile button */}
        {isMobile && (
          <Button
            onClick={handleMobileAuth}
            className="w-full"
            variant="glassPrimary"
            size="lg"
          >
            <Smartphone className="w-5 h-5 mr-2" />
            Open Privado ID Wallet
          </Button>
        )}

        {/* Desktop: also show button as fallback */}
        {!isMobile && (
          <div className="pt-4 border-t border-white/10">
            <p className="text-xs text-white/70 text-center mb-3">
              Or open the wallet on this device
            </p>
            <Button
              onClick={handleMobileAuth}
              className="w-full"
              variant="outline"
              size="sm"
            >
              <ExternalLink className="w-4 h-4 mr-2" />
              Open Wallet App
            </Button>
          </div>
        )}

        {/* Polling indicator */}
        <div className="flex items-center justify-center gap-2 text-white/70 text-sm" role="status" aria-live="polite">
          <Loader2 className="w-4 h-4 animate-spin" aria-hidden="true" />
          <span>Waiting for wallet confirmation...</span>
        </div>
      </div>
    );
  };

  return (
    <div className="min-h-screen bg-mesh flex items-center justify-center p-4 overflow-x-hidden" data-testid="login-page">
      <div className="w-full max-w-md animate-fade-in-up">
        {/* Logo Header */}
        <div className="text-center mb-8" data-testid="login-header">
          <div className="w-16 h-16 mx-auto mb-4 rounded-2xl bg-gradient-to-br from-primary-500 to-accent-500 flex items-center justify-center shadow-lg shadow-primary-500/30">
            <Shield className="w-8 h-8 text-white" />
          </div>
          <h1 className="text-2xl font-bold text-white/95">Privacy Proxy</h1>
          <p className="text-white/80 mt-1">Authenticated RPC Access</p>
        </div>

        {/* Auth Card */}
        <Card variant="glassSolid" data-testid="auth-card">
          <CardHeader className="text-center">
            <CardTitle data-testid="auth-title">Authenticate with Privado ID</CardTitle>
            <CardDescription>
              Prove your humanity using zero-knowledge proofs
            </CardDescription>
          </CardHeader>
          <CardContent>
            {/* Loading state */}
            {state.step === 'loading' && (
              <div className="flex flex-col items-center gap-4 py-8" role="status" aria-live="polite" data-testid="auth-loading">
                <Loader2 className="w-8 h-8 animate-spin text-primary-400" aria-hidden="true" />
                <p className="text-white/80">Preparing authentication...</p>
              </div>
            )}

            {/* Ready state - show QR */}
            {state.step === 'ready' && renderQRSection()}

            {/* Success state */}
            {state.step === 'success' && (
              <div className="flex flex-col items-center gap-4 py-8" data-testid="auth-success">
                <div className="w-16 h-16 rounded-full bg-green-500/20 flex items-center justify-center">
                  <CheckCircle2 className="w-8 h-8 text-green-400" />
                </div>
                <p className="text-white/90 font-medium">Authentication successful!</p>
                <p className="text-white/80 text-sm">Redirecting to wallet linking...</p>
              </div>
            )}

            {/* Humanity verification required */}
            {state.step === 'humanity_required' && (
              <div className="flex flex-col items-center gap-4 py-6">
                <div className="w-16 h-16 rounded-full bg-yellow-500/20 flex items-center justify-center">
                  <AlertCircle className="w-8 h-8 text-yellow-400" />
                </div>
                <div className="text-center">
                  <p className="text-white/90 font-medium mb-2">Humanity Verification Required</p>
                  <p className="text-white/80 text-sm mb-4">
                    Please complete your ProofOfHumanity verification with Billions to continue.
                  </p>
                </div>
                <Button
                  onClick={() => window.open(state.humanityVerifyUrl!, '_blank')}
                  variant="glassPrimary"
                  size="lg"
                  className="w-full"
                >
                  <ExternalLink className="w-5 h-5 mr-2" />
                  Verify on Billions
                </Button>
                <Button
                  onClick={startAuth}
                  variant="outline"
                  size="sm"
                  className="w-full mt-2"
                >
                  Try Again
                </Button>
              </div>
            )}

            {/* Error state */}
            {state.step === 'error' && (
              <div className="flex flex-col items-center gap-4 py-6" data-testid="auth-error">
                <div className="w-16 h-16 rounded-full bg-red-500/20 flex items-center justify-center">
                  <AlertCircle className="w-8 h-8 text-red-400" />
                </div>
                <div className="text-center">
                  <p className="text-white/90 font-medium mb-2">Authentication Failed</p>
                  <p className="text-white/80 text-sm">{state.error}</p>
                </div>
                <Button onClick={startAuth} variant="glassPrimary" className="w-full mt-2" data-testid="try-again-btn">
                  Try Again
                </Button>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Help text */}
        <div className="mt-6 text-center">
          <p className="text-white/70 text-sm">
            Don't have Privado ID?{' '}
            <a
              href="https://docs.privado.id/docs/wallet/wallet-app/privadoid-app/"
              target="_blank"
              rel="noopener noreferrer"
              className="text-primary-400 hover:text-primary-300 underline underline-offset-2"
            >
              Download the wallet
            </a>
          </p>
        </div>

        {/* Mock login - requires explicit opt-in via VITE_ALLOW_MOCK_LOGIN=true */}
        {allowMockLogin && (
          <div className="mt-6 pt-6 border-t border-white/10" data-testid="dev-tools">
            <div className="text-center mb-3">
              <span className="inline-flex items-center gap-1.5 px-2 py-1 rounded-full bg-yellow-500/20 text-yellow-400 text-xs font-medium">
                <FlaskConical className="w-3 h-3" />
                Development Only
              </span>
            </div>
            <Button
              onClick={handleMockLogin}
              variant="outline"
              className="w-full border-yellow-500/30 text-yellow-400 hover:bg-yellow-500/10"
              disabled={state.step === 'loading'}
              data-testid="mock-login-btn"
            >
              {state.step === 'loading' ? (
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
              ) : (
                <FlaskConical className="w-4 h-4 mr-2" />
              )}
              Mock Login (Skip Wallet)
            </Button>
          </div>
        )}
      </div>
    </div>
  );
}
