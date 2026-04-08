import { connectorsForWallets, WalletList } from '@rainbow-me/rainbowkit';
import {
  metaMaskWallet,
  walletConnectWallet,
  rainbowWallet,
  injectedWallet,
} from '@rainbow-me/rainbowkit/wallets';
import { createConfig, http } from 'wagmi';
import { mainnet, polygon, arbitrum, optimism, base } from 'wagmi/chains';

// WalletConnect project ID - get one at https://cloud.walletconnect.com/
// Only include WalletConnect wallet when a valid project ID is configured
const projectId = import.meta.env.VITE_WALLETCONNECT_PROJECT_ID || '';
const hasWalletConnect = projectId.length > 0;

// Build wallet list based on available configuration
const wallets: WalletList = [
  {
    groupName: 'Popular',
    wallets: [
      metaMaskWallet,
      injectedWallet,
      // Only include WalletConnect-dependent wallets when projectId is available
      ...(hasWalletConnect ? [rainbowWallet, walletConnectWallet] : []),
    ],
  },
];

// Explicitly define wallets to exclude Coinbase (which pulls in LGPL dependencies)
const connectors = connectorsForWallets(wallets, {
  appName: 'Open Privacy Suite',
  projectId: projectId || 'placeholder', // RainbowKit requires a non-empty string
});

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

// Get RPC endpoint URL for the backend.
// The frontend dev server (port 5173) is NOT the RPC endpoint — the backend
// runs on a different port (default 8080). Use VITE_BACKEND_URL when set,
// otherwise infer by replacing the current origin's port with 8080.
export function getRpcEndpoint(): string {
  const backendUrl = import.meta.env.VITE_BACKEND_URL;
  if (backendUrl) {
    return `${backendUrl}/rpc`;
  }
  // Default: backend runs on port 8080 on the same host
  const url = new URL(window.location.origin);
  url.port = '8080';
  return `${url.origin}/rpc`;
}

// Generate Add to MetaMask params
export function getAddNetworkParams() {
  const rpcUrl = getRpcEndpoint();

  return {
    chainId: '0x1', // Mainnet - adjust based on actual chain
    chainName: 'Open Privacy Suite (Mainnet)',
    nativeCurrency: {
      name: 'Ether',
      symbol: 'ETH',
      decimals: 18,
    },
    rpcUrls: [rpcUrl],
    blockExplorerUrls: ['https://etherscan.io'],
  };
}
