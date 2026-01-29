import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Copy, Check, Wallet, Key, RefreshCw, FileKey } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { AlertDialog } from '@/components/ui/ConfirmDialog';
import { useAuth } from '@/contexts/AuthContext';
import { ethLinkApiMethods, EthAddressResponse } from '@/api/auth';
import { getRpcEndpoint, getAddNetworkParams } from '@/config/wagmi';

export function SuccessPage() {
  const navigate = useNavigate();
  const { isAuthenticated, accessToken, userDID, logout, isLoading } = useAuth();
  const [copied, setCopied] = useState<string | null>(null);
  const [linkedAddresses, setLinkedAddresses] = useState<EthAddressResponse[]>([]);
  const [isAddingNetwork, setIsAddingNetwork] = useState(false);
  const [showMetaMaskError, setShowMetaMaskError] = useState(false);

  const rpcEndpoint = getRpcEndpoint();

  // Redirect if not authenticated (wait for auth to load first)
  useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      navigate('/login');
    }
  }, [isAuthenticated, isLoading, navigate]);

  // Load linked addresses
  useEffect(() => {
    if (!accessToken) return;

    const loadAddresses = async () => {
      try {
        const response = await ethLinkApiMethods.getAddresses(accessToken);
        setLinkedAddresses(response.addresses);
      } catch {
        // No addresses
      }
    };

    loadAddresses();
  }, [accessToken]);

  // Copy to clipboard with fallback for mobile
  const copyToClipboard = async (text: string, type: string) => {
    try {
      // Try modern clipboard API first
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        // Fallback for older browsers/mobile
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.left = '-999999px';
        textArea.style.top = '-999999px';
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        document.execCommand('copy');
        document.body.removeChild(textArea);
      }
      setCopied(type);
      setTimeout(() => setCopied(null), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
      // Show the text in a prompt as last resort
      window.prompt('Copy this text:', text);
    }
  };

  // Add network to MetaMask
  const handleAddToMetaMask = async () => {
    if (!window.ethereum) {
      setShowMetaMaskError(true);
      return;
    }

    setIsAddingNetwork(true);
    try {
      const params = getAddNetworkParams();
      await window.ethereum.request({
        method: 'wallet_addEthereumChain',
        params: [params],
      });
    } catch (err) {
      console.error('Failed to add network:', err);
    } finally {
      setIsAddingNetwork(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#F1F5F9] flex items-center justify-center p-4" data-testid="success-page">
      <div className="w-full max-w-lg animate-fade-in-up">
        {/* Success Header */}
        <div className="text-center mb-8" data-testid="success-header">
          <div className="w-20 h-20 mx-auto mb-4 rounded-2xl bg-gradient-to-br from-[#8950FA] to-[#A478FC] flex items-center justify-center shadow-lg shadow-primary animate-scale-in">
            <Shield className="w-10 h-10 text-white" />
          </div>
          <h1 className="text-3xl font-bold text-[#0F0F0F]" data-testid="success-title">You're All Set!</h1>
          <p className="text-[#6B7280] mt-2">
            Your authenticated RPC endpoint is ready to use
          </p>
        </div>

        {/* RPC Endpoint Card */}
        <Card variant="default" className="mb-4" data-testid="rpc-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Key className="w-5 h-5 text-[#8950FA]" />
              Your RPC Endpoint
            </CardTitle>
            <CardDescription>
              Use this endpoint in your dApps and wallets
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* RPC URL */}
            <div className="space-y-2">
              <label className="text-xs text-[#94A3B8] uppercase tracking-wide">
                RPC URL
              </label>
              <div className="flex items-center gap-2">
                <code className="flex-1 p-3 bg-[#F1F5F9] rounded-lg font-mono text-sm text-[#0F0F0F] overflow-x-auto" data-testid="rpc-endpoint">
                  {rpcEndpoint}
                </code>
                <Button
                  onClick={() => copyToClipboard(rpcEndpoint, 'rpc')}
                  variant="outline"
                  size="icon"
                  className="flex-shrink-0"
                  data-testid="copy-rpc-btn"
                >
                  {copied === 'rpc' ? (
                    <Check className="w-4 h-4 text-[#166534]" />
                  ) : (
                    <Copy className="w-4 h-4" />
                  )}
                </Button>
              </div>
            </div>

            {/* Access Token */}
            {accessToken && (
              <div className="space-y-2">
                <label className="text-xs text-[#94A3B8] uppercase tracking-wide">
                  Access Token (for Authorization header)
                </label>
                <div className="flex items-center gap-2">
                  <code className="flex-1 p-3 bg-[#F1F5F9] rounded-lg font-mono text-xs text-[#374151] overflow-hidden text-ellipsis">
                    Bearer {accessToken.slice(0, 20)}...{accessToken.slice(-10)}
                  </code>
                  <Button
                    onClick={() => copyToClipboard(`Bearer ${accessToken}`, 'token')}
                    variant="outline"
                    size="icon"
                    className="flex-shrink-0"
                  >
                    {copied === 'token' ? (
                      <Check className="w-4 h-4 text-[#166534]" />
                    ) : (
                      <Copy className="w-4 h-4" />
                    )}
                  </Button>
                </div>
              </div>
            )}

            {/* Add to MetaMask */}
            <Button
              onClick={handleAddToMetaMask}
              variant="default"
              className="w-full"
              disabled={isAddingNetwork}
              data-testid="add-metamask-btn"
            >
              {isAddingNetwork ? (
                <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
              ) : (
                <svg className="w-5 h-5 mr-2" viewBox="0 0 35 33" fill="none" xmlns="http://www.w3.org/2000/svg">
                  <path d="M32.9582 1L19.8241 10.7183L22.2665 4.99099L32.9582 1Z" fill="#E17726" stroke="#E17726" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M2.04858 1L15.0707 10.809L12.7396 4.99098L2.04858 1Z" fill="#E27625" stroke="#E27625" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M28.2292 23.5334L24.7346 28.872L32.2175 30.9323L34.3611 23.6501L28.2292 23.5334Z" fill="#E27625" stroke="#E27625" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M0.658203 23.6501L2.79013 30.9323L10.2614 28.872L6.77844 23.5334L0.658203 23.6501Z" fill="#E27625" stroke="#E27625" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M9.87524 14.5149L7.79297 17.6507L15.1838 17.9891L14.9369 9.97729L9.87524 14.5149Z" fill="#E27625" stroke="#E27625" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M25.1313 14.5149L19.9929 9.88647L19.824 17.9891L27.2149 17.6507L25.1313 14.5149Z" fill="#E27625" stroke="#E27625" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M10.2614 28.872L14.7347 26.7067L10.8714 23.7034L10.2614 28.872Z" fill="#E27625" stroke="#E27625" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M20.2715 26.7067L24.7346 28.872L24.1363 23.7034L20.2715 26.7067Z" fill="#E27625" stroke="#E27625" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M24.7346 28.8721L20.2715 26.7068L20.6352 29.6168L20.5986 30.8407L24.7346 28.8721Z" fill="#D5BFB2" stroke="#D5BFB2" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M10.2614 28.8721L14.4091 30.8407L14.3842 29.6168L14.7347 26.7068L10.2614 28.8721Z" fill="#D5BFB2" stroke="#D5BFB2" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M14.4854 21.7842L10.7642 20.6903L13.3685 19.4897L14.4854 21.7842Z" fill="#233447" stroke="#233447" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M20.5208 21.7842L21.6377 19.4897L24.2536 20.6903L20.5208 21.7842Z" fill="#233447" stroke="#233447" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M10.2614 28.872L10.8948 23.5334L6.77844 23.6501L10.2614 28.872Z" fill="#CC6228" stroke="#CC6228" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M24.1113 23.5334L24.7347 28.872L28.2293 23.6501L24.1113 23.5334Z" fill="#CC6228" stroke="#CC6228" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M27.2149 17.6507L19.824 17.9891L20.5208 21.7842L21.6377 19.4897L24.2536 20.6903L27.2149 17.6507Z" fill="#CC6228" stroke="#CC6228" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M10.7643 20.6903L13.3685 19.4897L14.4854 21.7842L15.1839 17.9891L7.79297 17.6507L10.7643 20.6903Z" fill="#CC6228" stroke="#CC6228" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M7.79297 17.6507L10.8714 23.7034L10.7643 20.6903L7.79297 17.6507Z" fill="#E27625" stroke="#E27625" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M24.2536 20.6903L24.1364 23.7034L27.2149 17.6507L24.2536 20.6903Z" fill="#E27625" stroke="#E27625" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M15.1839 17.9891L14.4854 21.7842L15.3573 26.2285L15.5546 20.3519L15.1839 17.9891Z" fill="#E27625" stroke="#E27625" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M19.824 17.9891L19.4649 20.3402L19.6489 26.2285L20.5208 21.7842L19.824 17.9891Z" fill="#E27625" stroke="#E27625" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M20.5207 21.7842L19.6489 26.2285L20.2714 26.7068L24.1363 23.7034L24.2535 20.6903L20.5207 21.7842Z" fill="#F5841F" stroke="#F5841F" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M10.7642 20.6903L10.8714 23.7034L14.7346 26.7068L15.3572 26.2285L14.4853 21.7842L10.7642 20.6903Z" fill="#F5841F" stroke="#F5841F" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M20.5986 30.8407L20.6352 29.6168L20.2964 29.3251H14.7098L14.3842 29.6168L14.4091 30.8407L10.2614 28.8721L11.6684 30.0261L14.6566 32.1097H20.3447L23.3446 30.0261L24.7346 28.8721L20.5986 30.8407Z" fill="#C0AC9D" stroke="#C0AC9D" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M20.2715 26.7068L19.649 26.2285H15.3573L14.7348 26.7068L14.3843 29.6168L14.7099 29.3251H20.2965L20.6353 29.6168L20.2715 26.7068Z" fill="#161616" stroke="#161616" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M33.5167 11.3532L34.6585 5.98873L32.9582 1L20.2715 10.3799L25.1312 14.5149L32.0442 16.5286L33.5765 14.7384L32.9116 14.2601L33.9801 13.2845L33.1663 12.4922L34.2349 11.6649L33.5167 11.3532Z" fill="#763E1A" stroke="#763E1A" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M0.347656 5.98873L1.48956 11.3532L0.759557 11.6649L1.83988 12.4922L1.02615 13.2845L2.09481 14.2601L1.42989 14.7384L2.9622 16.5286L9.87528 14.5149L14.735 10.3799L2.04838 1L0.347656 5.98873Z" fill="#763E1A" stroke="#763E1A" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M32.0442 16.5285L25.1312 14.5149L27.2148 17.6507L24.1364 23.7034L28.2293 23.6501H34.361L32.0442 16.5285Z" fill="#F5841F" stroke="#F5841F" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M9.87534 14.5149L2.96226 16.5285L0.658203 23.6501H6.77844L10.8714 23.7034L7.79299 17.6507L9.87534 14.5149Z" fill="#F5841F" stroke="#F5841F" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                  <path d="M19.8241 17.989L20.2713 10.3799L22.2666 4.99097H12.7395L14.7348 10.3799L15.1837 17.989L15.3443 20.3635L15.3576 26.2285H19.6493L19.6626 20.3635L19.8241 17.989Z" fill="#F5841F" stroke="#F5841F" strokeWidth="0.25" strokeLinecap="round" strokeLinejoin="round"/>
                </svg>
              )}
              Add Network to MetaMask
            </Button>
          </CardContent>
        </Card>

        {/* Identity Info */}
        <Card variant="default" className="mb-4">
          <CardContent className="py-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3 min-w-0 flex-1">
                <div className="w-10 h-10 rounded-full bg-[#F5F3FF] flex items-center justify-center flex-shrink-0">
                  <Shield className="w-5 h-5 text-[#8950FA]" />
                </div>
                <div className="min-w-0 flex-1">
                  <p className="text-[#0F0F0F] text-sm font-medium">Privado ID</p>
                  <p className="text-[#94A3B8] text-xs font-mono truncate" title={userDID || 'Connected'}>
                    {userDID || 'Connected'}
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2 flex-shrink-0">
                {userDID && (
                  <Button
                    onClick={() => copyToClipboard(userDID, 'did')}
                    variant="ghost"
                    size="icon"
                    className="h-8 w-8"
                    title="Copy DID"
                  >
                    {copied === 'did' ? (
                      <Check className="w-4 h-4 text-[#166534]" />
                    ) : (
                      <Copy className="w-4 h-4 text-[#94A3B8]" />
                    )}
                  </Button>
                )}
                <div className="flex items-center gap-2 text-[#166534] text-xs">
                  <div className="w-2 h-2 rounded-full bg-[#22C55E] animate-pulse" />
                  Verified
                </div>
              </div>
            </div>

            {/* Linked wallets */}
            {linkedAddresses.length > 0 && (
              <div className="mt-4 pt-4 border-t border-[#E2E8F0]">
                <p className="text-xs text-[#94A3B8] mb-2">Linked Wallets</p>
                <div className="space-y-2">
                  {linkedAddresses.map((addr) => (
                    <div
                      key={addr.address}
                      className="flex items-center gap-2 p-2 bg-[#F1F5F9] rounded-lg"
                    >
                      <Wallet className="w-3 h-3 text-[#8950FA] flex-shrink-0" />
                      <span className="text-[#374151] font-mono text-xs break-all flex-1">
                        {addr.address}
                      </span>
                      <button
                        onClick={() => copyToClipboard(addr.address, addr.address)}
                        className="text-[#94A3B8] hover:text-[#374151] p-1 flex-shrink-0"
                        title="Copy address"
                      >
                        {copied === addr.address ? (
                          <Check className="w-3 h-3 text-[#166534]" />
                        ) : (
                          <Copy className="w-3 h-3" />
                        )}
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Usage Examples */}
        <Card variant="default">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Quick Start</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div>
              <p className="text-xs text-[#94A3B8] mb-1">cURL</p>
              <pre className="p-2 bg-[#F1F5F9] rounded text-xs font-mono text-[#374151] overflow-x-auto">
{`curl ${rpcEndpoint} \\
  -H "Authorization: Bearer <token>" \\
  -H "Content-Type: application/json" \\
  -d '{"method":"eth_blockNumber","params":[],"id":1,"jsonrpc":"2.0"}'`}
              </pre>
            </div>

            <div>
              <p className="text-xs text-[#94A3B8] mb-1">ethers.js</p>
              <pre className="p-2 bg-[#F1F5F9] rounded text-xs font-mono text-[#374151] overflow-x-auto">
{`const provider = new ethers.JsonRpcProvider(
  "${rpcEndpoint}",
  undefined,
  { headers: { "Authorization": "Bearer <token>" } }
);`}
              </pre>
            </div>
          </CardContent>
        </Card>

        {/* Actions */}
        <div className="mt-6 flex flex-col gap-3">
          <div className="flex items-center gap-3">
            <Button
              onClick={() => navigate('/link-wallet')}
              variant="outline"
              size="sm"
              className="flex-1"
            >
              <Wallet className="w-4 h-4 mr-2" />
              Manage Wallets
            </Button>
            <Button
              onClick={() => navigate('/disclosure')}
              variant="outline"
              size="sm"
              className="flex-1"
            >
              <FileKey className="w-4 h-4 mr-2" />
              Data Disclosure
            </Button>
          </div>
          <div className="text-center">
            <button
              onClick={logout}
              className="text-[#94A3B8] text-sm hover:text-[#6B7280]"
            >
              Sign out
            </button>
          </div>
        </div>

        {/* MetaMask Not Installed Alert */}
        <AlertDialog
          open={showMetaMaskError}
          onOpenChange={setShowMetaMaskError}
          title="MetaMask Not Found"
          description="MetaMask is not installed. Please install MetaMask to add this network."
          buttonLabel="OK"
          variant="warning"
        />
      </div>
    </div>
  );
}

