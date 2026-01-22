import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAccount, useSignMessage, useDisconnect } from 'wagmi';
import { ConnectButton } from '@rainbow-me/rainbowkit';
import { Wallet, Link2, Loader2, CheckCircle2, AlertCircle, ArrowRight, X, Copy, Check } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { useAuth } from '@/contexts/AuthContext';
import { ethLinkApiMethods, EthAddressResponse } from '@/api/auth';

type LinkStep = 'connect' | 'signing' | 'verifying' | 'success' | 'error';

interface LinkState {
  step: LinkStep;
  nonce: string | null;
  message: string | null;
  error: string | null;
  linkedAddresses: EthAddressResponse[];
}

export function LinkWalletPage() {
  const navigate = useNavigate();
  const { isAuthenticated, accessToken, logout, isLoading } = useAuth();
  const { address, isConnected } = useAccount();
  const { disconnect } = useDisconnect();
  const { signMessageAsync } = useSignMessage();

  const [state, setState] = useState<LinkState>({
    step: 'connect',
    nonce: null,
    message: null,
    error: null,
    linkedAddresses: [],
  });
  const [isLinking, setIsLinking] = useState(false);
  const [copiedAddress, setCopiedAddress] = useState<string | null>(null);

  // Copy address to clipboard
  const copyToClipboard = async (address: string) => {
    await navigator.clipboard.writeText(address);
    setCopiedAddress(address);
    setTimeout(() => setCopiedAddress(null), 2000);
  };

  // Redirect if not authenticated (wait for auth to load first)
  useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      navigate('/login');
    }
  }, [isAuthenticated, isLoading, navigate]);

  // Load existing linked addresses
  useEffect(() => {
    if (!accessToken) return;

    const loadAddresses = async () => {
      try {
        const response = await ethLinkApiMethods.getAddresses(accessToken);
        setState(prev => ({ ...prev, linkedAddresses: response.addresses }));
      } catch {
        // No linked addresses yet
      }
    };

    loadAddresses();
  }, [accessToken]);

  // Check if current address is already linked
  const isCurrentAddressLinked = address
    ? state.linkedAddresses.some(
        a => a.address.toLowerCase() === address.toLowerCase()
      )
    : false;

  // Handle wallet link
  const handleLinkWallet = async () => {
    if (!accessToken || !address || !isConnected) return;

    setIsLinking(true);
    setState(prev => ({ ...prev, step: 'signing', error: null }));

    try {
      // Step 1: Get challenge
      const challenge = await ethLinkApiMethods.getChallenge(accessToken);
      setState(prev => ({
        ...prev,
        nonce: challenge.nonce,
        message: challenge.message,
      }));

      // Step 2: Sign message
      const signature = await signMessageAsync({ message: challenge.message });

      setState(prev => ({ ...prev, step: 'verifying' }));

      // Step 3: Verify signature and link
      await ethLinkApiMethods.verifyLink(
        accessToken,
        challenge.nonce,
        address,
        signature
      );

      // Refresh linked addresses
      const response = await ethLinkApiMethods.getAddresses(accessToken);
      setState(prev => ({
        ...prev,
        step: 'success',
        linkedAddresses: response.addresses,
      }));
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to link wallet';
      setState(prev => ({ ...prev, step: 'error', error: errorMessage }));
    } finally {
      setIsLinking(false);
    }
  };

  // Handle unlink
  const handleUnlink = async (addressToUnlink: string) => {
    if (!accessToken) return;

    try {
      await ethLinkApiMethods.unlinkAddress(accessToken, addressToUnlink);
      setState(prev => ({
        ...prev,
        linkedAddresses: prev.linkedAddresses.filter(
          a => a.address.toLowerCase() !== addressToUnlink.toLowerCase()
        ),
      }));
    } catch {
      // Handle error silently or show toast
    }
  };

  // Continue to success page
  const handleContinue = () => {
    navigate('/success');
  };

  // Skip wallet linking
  const handleSkip = () => {
    navigate('/success');
  };

  return (
    <div className="min-h-screen bg-[#F1F5F9] flex items-center justify-center p-4" data-testid="link-wallet-page">
      <div className="w-full max-w-md animate-fade-in-up">
        {/* Header */}
        <div className="text-center mb-8" data-testid="link-wallet-header">
          <div className="w-16 h-16 mx-auto mb-4 rounded-2xl bg-gradient-to-br from-[#8950FA] to-[#A478FC] flex items-center justify-center shadow-lg shadow-primary">
            <Wallet className="w-8 h-8 text-white" />
          </div>
          <h1 className="text-2xl font-bold text-[#0F0F0F]">Link Your Wallet</h1>
          <p className="text-[#6B7280] mt-1">Connect an Ethereum address</p>
        </div>

        {/* Main Card */}
        <Card variant="default" data-testid="link-wallet-card">
          <CardHeader className="text-center">
            <CardTitle data-testid="link-wallet-title">Connect & Sign</CardTitle>
            <CardDescription>
              Link your Ethereum wallet to your identity for seamless RPC access
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            {/* Wallet Connection */}
            <div className="flex flex-col items-center gap-4">
              <ConnectButton.Custom>
                {({
                  account,
                  chain,
                  openConnectModal,
                  openChainModal,
                  mounted,
                }) => {
                  const connected = mounted && account && chain;

                  return (
                    <div className="w-full">
                      {!connected ? (
                        <Button
                          onClick={openConnectModal}
                          variant="default"
                          size="lg"
                          className="w-full"
                          data-testid="connect-wallet-btn"
                        >
                          <Wallet className="w-5 h-5 mr-2" />
                          Connect Wallet
                        </Button>
                      ) : (
                        <div className="bg-white rounded-xl border border-[#E2E8F0] shadow-card p-4 space-y-3" data-testid="wallet-connected">
                          <div className="flex items-center justify-between">
                            <div className="flex items-center gap-3">
                              <div className="w-10 h-10 rounded-full bg-[#F5F3FF] flex items-center justify-center">
                                <Wallet className="w-5 h-5 text-[#8950FA]" />
                              </div>
                              <div>
                                <p className="text-[#0F0F0F] font-medium text-sm" data-testid="wallet-address">
                                  {account.displayName}
                                </p>
                                <button
                                  onClick={openChainModal}
                                  className="text-xs text-[#94A3B8] hover:text-[#374151] flex items-center gap-1"
                                >
                                  {chain.name}
                                </button>
                              </div>
                            </div>
                            <button
                              onClick={() => disconnect()}
                              className="text-[#94A3B8] hover:text-[#374151] p-1"
                            >
                              <X className="w-4 h-4" />
                            </button>
                          </div>

                          {/* Link button */}
                          {!isCurrentAddressLinked ? (
                            <Button
                              onClick={handleLinkWallet}
                              disabled={isLinking}
                              variant="default"
                              className="w-full"
                              data-testid="sign-link-btn"
                            >
                              {isLinking ? (
                                <>
                                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                                  {state.step === 'signing' && 'Sign in wallet...'}
                                  {state.step === 'verifying' && 'Verifying...'}
                                </>
                              ) : (
                                <>
                                  <Link2 className="w-4 h-4 mr-2" />
                                  Sign & Link Address
                                </>
                              )}
                            </Button>
                          ) : (
                            <div className="flex items-center gap-2 text-[#166534] text-sm justify-center" data-testid="address-linked">
                              <CheckCircle2 className="w-4 h-4" />
                              Address linked
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  );
                }}
              </ConnectButton.Custom>
            </div>

            {/* Error display */}
            {state.step === 'error' && state.error && (
              <div className="flex items-start gap-3 p-3 bg-[#FEE2E2] border border-[#FECACA] rounded-lg">
                <AlertCircle className="w-5 h-5 text-[#991B1B] flex-shrink-0 mt-0.5" />
                <div>
                  <p className="text-[#991B1B] text-sm font-medium">Error</p>
                  <p className="text-[#7F1D1D] text-xs">{state.error}</p>
                </div>
              </div>
            )}

            {/* Linked Addresses List */}
            {state.linkedAddresses.length > 0 && (
              <div className="space-y-3" data-testid="linked-addresses">
                <h3 className="text-sm font-medium text-[#374151]">Linked Addresses</h3>
                <div className="space-y-2">
                  {state.linkedAddresses.map((linked) => (
                    <div
                      key={linked.address}
                      className="flex items-center justify-between p-3 bg-[#F1F5F9] rounded-lg gap-2"
                    >
                      <div className="flex items-center gap-2 min-w-0 flex-1">
                        <CheckCircle2 className="w-4 h-4 text-[#166534] flex-shrink-0" />
                        <span className="text-[#374151] font-mono text-xs break-all">
                          {linked.address}
                        </span>
                      </div>
                      <div className="flex items-center gap-2 flex-shrink-0">
                        <button
                          onClick={() => copyToClipboard(linked.address)}
                          className="text-[#94A3B8] hover:text-[#374151] p-1"
                          title="Copy address"
                        >
                          {copiedAddress === linked.address ? (
                            <Check className="w-4 h-4 text-[#166534]" />
                          ) : (
                            <Copy className="w-4 h-4" />
                          )}
                        </button>
                        <button
                          onClick={() => handleUnlink(linked.address)}
                          className="text-[#94A3B8] hover:text-[#991B1B] text-xs"
                        >
                          Unlink
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Action buttons */}
            <div className="flex flex-col gap-3 pt-4 border-t border-[#E2E8F0]">
              <Button
                onClick={handleContinue}
                variant="success"
                size="lg"
                className="w-full"
                disabled={state.linkedAddresses.length === 0}
                data-testid="continue-btn"
              >
                Continue
                <ArrowRight className="w-4 h-4 ml-2" />
              </Button>

              {state.linkedAddresses.length === 0 && (
                <Button
                  onClick={handleSkip}
                  variant="ghost"
                  size="sm"
                  className="w-full text-[#94A3B8]"
                  data-testid="skip-btn"
                >
                  Skip for now
                </Button>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Logout option */}
        <div className="mt-6 text-center">
          <button
            onClick={logout}
            className="text-[#94A3B8] text-sm hover:text-[#6B7280] underline underline-offset-2"
          >
            Sign out
          </button>
        </div>
      </div>
    </div>
  );
}
