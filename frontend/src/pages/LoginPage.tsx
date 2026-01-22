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
            <p className="text-sm text-[#6B7280] text-center">
              Scan with your Privado ID wallet
            </p>
          </div>
        )}

        {/* Mobile button */}
        {isMobile && (
          <Button
            onClick={handleMobileAuth}
            className="w-full"
            variant="default"
            size="lg"
          >
            <Smartphone className="w-5 h-5 mr-2" />
            Open Privado ID Wallet
          </Button>
        )}

        {/* Desktop: also show button as fallback */}
        {!isMobile && (
          <div className="pt-4 border-t border-[#E2E8F0]">
            <p className="text-xs text-[#374151] text-center mb-3">
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
        <div className="flex items-center justify-center gap-2 text-[#374151] text-sm" role="status" aria-live="polite">
          <Loader2 className="w-4 h-4 animate-spin" aria-hidden="true" />
          <span>Waiting for wallet confirmation...</span>
        </div>
      </div>
    );
  };

  return (
    <div className="min-h-screen bg-[#F1F5F9] flex items-center justify-center p-4 overflow-x-hidden" data-testid="login-page">
      <div className="w-full max-w-md animate-fade-in-up">
        {/* Logo Header */}
        <div className="text-center mb-8" data-testid="login-header">
          <div className="w-16 h-16 mx-auto mb-4 rounded-2xl bg-gradient-to-br from-[#8950FA] to-[#A478FC] flex items-center justify-center shadow-lg shadow-primary">
            <Shield className="w-8 h-8 text-white" />
          </div>
          <h1 className="text-2xl font-bold text-[#0F0F0F]">Privacy Proxy</h1>
          <p className="text-[#6B7280] mt-1">Authenticated RPC Access</p>
        </div>

        {/* Auth Card */}
        <Card variant="default" data-testid="auth-card">
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
                <Loader2 className="w-8 h-8 animate-spin text-[#8950FA]" aria-hidden="true" />
                <p className="text-[#6B7280]">Preparing authentication...</p>
              </div>
            )}

            {/* Ready state - show QR */}
            {state.step === 'ready' && renderQRSection()}

            {/* Success state */}
            {state.step === 'success' && (
              <div className="flex flex-col items-center gap-4 py-8" data-testid="auth-success">
                <div className="w-16 h-16 rounded-full bg-[#DCFCE7] flex items-center justify-center">
                  <CheckCircle2 className="w-8 h-8 text-[#166534]" />
                </div>
                <p className="text-[#0F0F0F] font-medium">Authentication successful!</p>
                <p className="text-[#6B7280] text-sm">Redirecting to wallet linking...</p>
              </div>
            )}

            {/* Humanity verification required */}
            {state.step === 'humanity_required' && (
              <div className="flex flex-col items-center gap-4 py-6">
                <div className="w-16 h-16 rounded-full bg-[#FEF9C3] flex items-center justify-center">
                  <AlertCircle className="w-8 h-8 text-[#854D0E]" />
                </div>
                <div className="text-center">
                  <p className="text-[#0F0F0F] font-medium mb-2">Humanity Verification Required</p>
                  <p className="text-[#6B7280] text-sm mb-4">
                    Please complete your ProofOfHumanity verification with Billions to continue.
                  </p>
                </div>
                <Button
                  onClick={() => window.open(state.humanityVerifyUrl!, '_blank')}
                  variant="default"
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
                <div className="w-16 h-16 rounded-full bg-[#FEE2E2] flex items-center justify-center">
                  <AlertCircle className="w-8 h-8 text-[#991B1B]" />
                </div>
                <div className="text-center">
                  <p className="text-[#0F0F0F] font-medium mb-2">Authentication Failed</p>
                  <p className="text-[#6B7280] text-sm">{state.error}</p>
                </div>
                <Button onClick={startAuth} variant="default" className="w-full mt-2" data-testid="try-again-btn">
                  Try Again
                </Button>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Help text */}
        <div className="mt-6 text-center">
          <p className="text-[#374151] text-sm">
            Don't have Privado ID?{' '}
            <a
              href="https://docs.privado.id/docs/wallet/wallet-app/privadoid-app/"
              target="_blank"
              rel="noopener noreferrer"
              className="text-[#8950FA] hover:text-[#A478FC] underline underline-offset-2"
            >
              Download the wallet
            </a>
          </p>
        </div>

        {/* Mock login - requires explicit opt-in via VITE_ALLOW_MOCK_LOGIN=true */}
        {allowMockLogin && (
          <div className="mt-6 pt-6 border-t border-[#E2E8F0]" data-testid="dev-tools">
            <div className="text-center mb-3">
              <span className="inline-flex items-center gap-1.5 px-2 py-1 rounded-full bg-[#FEF9C3] text-[#854D0E] text-xs font-medium">
                <FlaskConical className="w-3 h-3" />
                Development Only
              </span>
            </div>
            <Button
              onClick={handleMockLogin}
              variant="outline"
              className="w-full border-[#FDE047] text-[#854D0E] hover:bg-[#FEF9C3]"
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
