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
  const { isAuthenticated, accessToken, logout } = useAuth();
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

  // Redirect if not authenticated
  useEffect(() => {
    if (!isAuthenticated) {
      navigate('/login');
    }
  }, [isAuthenticated, navigate]);

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
    <div className="min-h-screen bg-mesh flex items-center justify-center p-4">
      <div className="w-full max-w-md animate-fade-in-up">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="w-16 h-16 mx-auto mb-4 rounded-2xl bg-gradient-to-br from-accent-500 to-primary-500 flex items-center justify-center shadow-lg shadow-accent-500/30">
            <Wallet className="w-8 h-8 text-white" />
          </div>
          <h1 className="text-2xl font-bold text-white/95">Link Your Wallet</h1>
          <p className="text-white/60 mt-1">Connect an Ethereum address</p>
        </div>

        {/* Main Card */}
        <Card variant="glassSolid">
          <CardHeader className="text-center">
            <CardTitle>Connect & Sign</CardTitle>
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
                          variant="glassPrimary"
                          size="lg"
                          className="w-full"
                        >
                          <Wallet className="w-5 h-5 mr-2" />
                          Connect Wallet
                        </Button>
                      ) : (
                        <div className="glass-card p-4 space-y-3">
                          <div className="flex items-center justify-between">
                            <div className="flex items-center gap-3">
                              <div className="w-10 h-10 rounded-full bg-accent-500/20 flex items-center justify-center">
                                <Wallet className="w-5 h-5 text-accent-400" />
                              </div>
                              <div>
                                <p className="text-white/90 font-medium text-sm">
                                  {account.displayName}
                                </p>
                                <button
                                  onClick={openChainModal}
                                  className="text-xs text-white/50 hover:text-white/70 flex items-center gap-1"
                                >
                                  {chain.name}
                                </button>
                              </div>
                            </div>
                            <button
                              onClick={() => disconnect()}
                              className="text-white/40 hover:text-white/70 p-1"
                            >
                              <X className="w-4 h-4" />
                            </button>
                          </div>

                          {/* Link button */}
                          {!isCurrentAddressLinked ? (
                            <Button
                              onClick={handleLinkWallet}
                              disabled={isLinking}
                              variant="glassPrimary"
                              className="w-full"
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
                            <div className="flex items-center gap-2 text-green-400 text-sm justify-center">
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
              <div className="flex items-start gap-3 p-3 bg-red-500/10 border border-red-500/20 rounded-lg">
                <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
                <div>
                  <p className="text-red-400 text-sm font-medium">Error</p>
                  <p className="text-red-300/70 text-xs">{state.error}</p>
                </div>
              </div>
            )}

            {/* Linked Addresses List */}
            {state.linkedAddresses.length > 0 && (
              <div className="space-y-3">
                <h3 className="text-sm font-medium text-white/70">Linked Addresses</h3>
                <div className="space-y-2">
                  {state.linkedAddresses.map((linked) => (
                    <div
                      key={linked.address}
                      className="flex items-center justify-between p-3 bg-white/5 rounded-lg gap-2"
                    >
                      <div className="flex items-center gap-2 min-w-0 flex-1">
                        <CheckCircle2 className="w-4 h-4 text-green-400 flex-shrink-0" />
                        <span className="text-white/80 font-mono text-xs break-all">
                          {linked.address}
                        </span>
                      </div>
                      <div className="flex items-center gap-2 flex-shrink-0">
                        <button
                          onClick={() => copyToClipboard(linked.address)}
                          className="text-white/40 hover:text-white/70 p-1"
                          title="Copy address"
                        >
                          {copiedAddress === linked.address ? (
                            <Check className="w-4 h-4 text-green-400" />
                          ) : (
                            <Copy className="w-4 h-4" />
                          )}
                        </button>
                        <button
                          onClick={() => handleUnlink(linked.address)}
                          className="text-white/40 hover:text-red-400 text-xs"
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
            <div className="flex flex-col gap-3 pt-4 border-t border-white/10">
              <Button
                onClick={handleContinue}
                variant="success"
                size="lg"
                className="w-full"
                disabled={state.linkedAddresses.length === 0}
              >
                Continue
                <ArrowRight className="w-4 h-4 ml-2" />
              </Button>

              {state.linkedAddresses.length === 0 && (
                <Button
                  onClick={handleSkip}
                  variant="ghost"
                  size="sm"
                  className="w-full text-white/50"
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
            className="text-white/40 text-sm hover:text-white/60 underline underline-offset-2"
          >
            Sign out
          </button>
        </div>
      </div>
    </div>
  );
}
