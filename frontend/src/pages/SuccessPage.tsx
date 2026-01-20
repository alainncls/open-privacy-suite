import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Copy, Check, Wallet, Key, RefreshCw } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { useAuth } from '@/contexts/AuthContext';
import { ethLinkApiMethods, EthAddressResponse } from '@/api/auth';
import { getRpcEndpoint, getAddNetworkParams } from '@/config/wagmi';

export function SuccessPage() {
  const navigate = useNavigate();
  const { isAuthenticated, accessToken, userDID, logout } = useAuth();
  const [copied, setCopied] = useState<'rpc' | 'token' | null>(null);
  const [linkedAddresses, setLinkedAddresses] = useState<EthAddressResponse[]>([]);
  const [isAddingNetwork, setIsAddingNetwork] = useState(false);

  const rpcEndpoint = getRpcEndpoint();

  // Redirect if not authenticated
  useEffect(() => {
    if (!isAuthenticated) {
      navigate('/login');
    }
  }, [isAuthenticated, navigate]);

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

  // Copy to clipboard
  const copyToClipboard = async (text: string, type: 'rpc' | 'token') => {
    await navigator.clipboard.writeText(text);
    setCopied(type);
    setTimeout(() => setCopied(null), 2000);
  };

  // Add network to MetaMask
  const handleAddToMetaMask = async () => {
    if (!window.ethereum) {
      alert('MetaMask is not installed');
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
    <div className="min-h-screen bg-mesh flex items-center justify-center p-4">
      <div className="w-full max-w-lg animate-fade-in-up">
        {/* Success Header */}
        <div className="text-center mb-8">
          <div className="w-20 h-20 mx-auto mb-4 rounded-2xl bg-gradient-to-br from-green-500 to-accent-500 flex items-center justify-center shadow-lg shadow-green-500/30 animate-scale-in">
            <Shield className="w-10 h-10 text-white" />
          </div>
          <h1 className="text-3xl font-bold text-white/95">You're All Set!</h1>
          <p className="text-white/60 mt-2">
            Your authenticated RPC endpoint is ready to use
          </p>
        </div>

        {/* RPC Endpoint Card */}
        <Card variant="glassSolid" className="mb-4">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Key className="w-5 h-5 text-primary-400" />
              Your RPC Endpoint
            </CardTitle>
            <CardDescription>
              Use this endpoint in your dApps and wallets
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* RPC URL */}
            <div className="space-y-2">
              <label className="text-xs text-white/50 uppercase tracking-wide">
                RPC URL
              </label>
              <div className="flex items-center gap-2">
                <code className="flex-1 p-3 bg-black/30 rounded-lg font-mono text-sm text-white/90 overflow-x-auto">
                  {rpcEndpoint}
                </code>
                <Button
                  onClick={() => copyToClipboard(rpcEndpoint, 'rpc')}
                  variant="outline"
                  size="icon"
                  className="flex-shrink-0"
                >
                  {copied === 'rpc' ? (
                    <Check className="w-4 h-4 text-green-400" />
                  ) : (
                    <Copy className="w-4 h-4" />
                  )}
                </Button>
              </div>
            </div>

            {/* Access Token */}
            {accessToken && (
              <div className="space-y-2">
                <label className="text-xs text-white/50 uppercase tracking-wide">
                  Access Token (for Authorization header)
                </label>
                <div className="flex items-center gap-2">
                  <code className="flex-1 p-3 bg-black/30 rounded-lg font-mono text-xs text-white/70 overflow-hidden text-ellipsis">
                    Bearer {accessToken.slice(0, 20)}...{accessToken.slice(-10)}
                  </code>
                  <Button
                    onClick={() => copyToClipboard(`Bearer ${accessToken}`, 'token')}
                    variant="outline"
                    size="icon"
                    className="flex-shrink-0"
                  >
                    {copied === 'token' ? (
                      <Check className="w-4 h-4 text-green-400" />
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
              variant="glassPrimary"
              className="w-full"
              disabled={isAddingNetwork}
            >
              {isAddingNetwork ? (
                <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
              ) : (
                <img
                  src="https://raw.githubusercontent.com/MetaMask/brand-resources/master/SVG/SVG_MetaMask_Icon_Color.svg"
                  alt="MetaMask"
                  className="w-5 h-5 mr-2"
                />
              )}
              Add Network to MetaMask
            </Button>
          </CardContent>
        </Card>

        {/* Identity Info */}
        <Card variant="glass" className="mb-4">
          <CardContent className="py-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-full bg-primary-500/20 flex items-center justify-center">
                  <Shield className="w-5 h-5 text-primary-400" />
                </div>
                <div>
                  <p className="text-white/90 text-sm font-medium">Privado ID</p>
                  <p className="text-white/50 text-xs font-mono">
                    {userDID ? `${userDID.slice(0, 20)}...` : 'Connected'}
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2 text-green-400 text-xs">
                <div className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
                Verified
              </div>
            </div>

            {/* Linked wallets */}
            {linkedAddresses.length > 0 && (
              <div className="mt-4 pt-4 border-t border-white/10">
                <p className="text-xs text-white/50 mb-2">Linked Wallets</p>
                <div className="flex flex-wrap gap-2">
                  {linkedAddresses.map((addr) => (
                    <div
                      key={addr.address}
                      className="flex items-center gap-1.5 px-2 py-1 bg-white/5 rounded-full text-xs"
                    >
                      <Wallet className="w-3 h-3 text-accent-400" />
                      <span className="text-white/70 font-mono">
                        {addr.address.slice(0, 6)}...{addr.address.slice(-4)}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Usage Examples */}
        <Card variant="glass">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Quick Start</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div>
              <p className="text-xs text-white/50 mb-1">cURL</p>
              <pre className="p-2 bg-black/30 rounded text-xs font-mono text-white/70 overflow-x-auto">
{`curl ${rpcEndpoint} \\
  -H "Authorization: Bearer <token>" \\
  -H "Content-Type: application/json" \\
  -d '{"method":"eth_blockNumber","params":[],"id":1,"jsonrpc":"2.0"}'`}
              </pre>
            </div>

            <div>
              <p className="text-xs text-white/50 mb-1">ethers.js</p>
              <pre className="p-2 bg-black/30 rounded text-xs font-mono text-white/70 overflow-x-auto">
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
        <div className="mt-6 flex items-center justify-between">
          <Button
            onClick={() => navigate('/link-wallet')}
            variant="outline"
            size="sm"
          >
            <Wallet className="w-4 h-4 mr-2" />
            Manage Wallets
          </Button>

          <button
            onClick={logout}
            className="text-white/40 text-sm hover:text-white/60"
          >
            Sign out
          </button>
        </div>
      </div>
    </div>
  );
}

