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
  appName: 'Privacy Proxy',
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

// Get RPC endpoint URL based on current origin
export function getRpcEndpoint(): string {
  const origin = window.location.origin;
  // The RPC endpoint is at /rpc path
  return `${origin}/rpc`;
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
