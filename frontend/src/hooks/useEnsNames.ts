import { useQuery } from '@tanstack/react-query';
import { createPublicClient, http } from 'viem';
import { mainnet } from 'viem/chains';

const mainnetClient = createPublicClient({
  chain: mainnet,
  transport: http(),
});

export function useEnsNames(addresses: string[]) {
  return useQuery({
    queryKey: ['ensNames', addresses.sort().join(',')],
    queryFn: async () => {
      const results: Record<string, string | null> = {};
      await Promise.all(
        addresses.map(async (addr) => {
          try {
            const ensName = await mainnetClient.getEnsName({
              address: addr as `0x${string}`,
            });
            results[addr.toLowerCase()] = ensName;
          } catch {
            results[addr.toLowerCase()] = null;
          }
        })
      );
      return results;
    },
    enabled: addresses.length > 0,
    staleTime: 1000 * 60 * 60, // Cache 1 hour
  });
}
