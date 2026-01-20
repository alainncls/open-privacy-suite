import { getDefaultConfig } from '@rainbow-me/rainbowkit';
import { mainnet, polygon, arbitrum, optimism, base } from 'wagmi/chains';

// RainbowKit configuration
export const wagmiConfig = getDefaultConfig({
  appName: 'Privacy Proxy',
  projectId: 'privacy-proxy-dev', // For development - replace with real WalletConnect project ID in production
  chains: [mainnet, polygon, arbitrum, optimism, base],
  ssr: false,
});

// Get RPC endpoint URL based on current origin
export function getRpcEndpoint(): string {
  const origin = window.location.origin;
  // The RPC endpoint is the same as the API server
  return origin;
}

// Generate Add to MetaMask params
export function getAddNetworkParams() {
  const rpcUrl = getRpcEndpoint();

  return {
    chainId: '0x1', // Mainnet - adjust based on actual chain
    chainName: 'Privacy Proxy (Mainnet)',
    nativeCurrency: {
      name: 'Ether',
      symbol: 'ETH',
      decimals: 18,
    },
    rpcUrls: [rpcUrl],
    blockExplorerUrls: ['https://etherscan.io'],
  };
}
