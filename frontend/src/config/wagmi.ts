import { connectorsForWallets } from '@rainbow-me/rainbowkit';
import {
  metaMaskWallet,
  walletConnectWallet,
  rainbowWallet,
  injectedWallet,
} from '@rainbow-me/rainbowkit/wallets';
import { createConfig, http } from 'wagmi';
import { mainnet, polygon, arbitrum, optimism, base } from 'wagmi/chains';

const projectId = 'privacy-proxy-dev'; // For development - replace with real WalletConnect project ID in production

// Explicitly define wallets to exclude Coinbase (which pulls in LGPL dependencies)
const connectors = connectorsForWallets(
  [
    {
      groupName: 'Popular',
      wallets: [
        metaMaskWallet,
        rainbowWallet,
        walletConnectWallet,
        injectedWallet,
      ],
    },
  ],
  {
    appName: 'Privacy Proxy',
    projectId,
  }
);

// RainbowKit configuration
export const wagmiConfig = createConfig({
  connectors,
  chains: [mainnet, polygon, arbitrum, optimism, base],
  transports: {
    [mainnet.id]: http(),
    [polygon.id]: http(),
    [arbitrum.id]: http(),
    [optimism.id]: http(),
    [base.id]: http(),
  },
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
