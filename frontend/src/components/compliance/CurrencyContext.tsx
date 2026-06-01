import { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { complianceApi } from '@/api/compliance';
import type { CurrencyInfo, CurrencySwitchConflict } from '@/types/compliance';

export class CurrencyConflictError extends Error {
  public conflict: CurrencySwitchConflict;
  constructor(conflict: CurrencySwitchConflict) {
    super(conflict.error);
    this.name = 'CurrencyConflictError';
    this.conflict = conflict;
  }
}

interface CurrencyContextType {
  currency: string;
  currencyInfo: CurrencyInfo | null;
  allCurrencies: CurrencyInfo[];
  setCurrency: (code: string, force?: boolean) => Promise<void>;
  formatAmount: (amount: number) => string;
  currencyLabel: string; // e.g. "USD", "EUR"
  loading: boolean;
  coingeckoEnabled: boolean;
}

const CurrencyContext = createContext<CurrencyContextType | null>(null);

const DEFAULT_CURRENCY_INFO: CurrencyInfo = { code: 'usd', name: 'US Dollar', symbol: '$' };

export function CurrencyProvider({ children }: { children: React.ReactNode }) {
  const [currency, setCurrencyState] = useState('usd');
  const [allCurrencies, setAllCurrencies] = useState<CurrencyInfo[]>([DEFAULT_CURRENCY_INFO]);
  const [loading, setLoading] = useState(true);
  const [coingeckoEnabled, setCoingeckoEnabled] = useState(true);

  const loadCurrency = useCallback(async () => {
    try {
      const response = await complianceApi.currency.get();
      const data = response.data;
      setCurrencyState(data.currency || 'usd');
      if (data.all_currencies?.length) {
        setAllCurrencies(data.all_currencies);
      }
      setCoingeckoEnabled(data.coingecko_enabled ?? true);
    } catch {
      // Fallback to USD
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadCurrency();
  }, [loadCurrency]);

  const setCurrency = useCallback(async (code: string, force?: boolean) => {
    try {
      await complianceApi.currency.set(code, force);
      setCurrencyState(code);
    } catch (err: unknown) {
      if (err && typeof err === 'object' && 'response' in err) {
        const axiosErr = err as { response?: { status?: number; data?: CurrencySwitchConflict } };
        if (axiosErr.response?.status === 409 && axiosErr.response?.data?.affected_tokens) {
          throw new CurrencyConflictError(axiosErr.response.data);
        }
      }
      throw err;
    }
  }, []);

  const currencyInfo = allCurrencies.find(c => c.code === currency) || DEFAULT_CURRENCY_INFO;

  const formatAmount = useCallback((amount: number) => {
    const info = allCurrencies.find(c => c.code === currency) || DEFAULT_CURRENCY_INFO;
    return `${info.symbol}${amount.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
  }, [currency, allCurrencies]);

  const currencyLabel = currency.toUpperCase();

  return (
    <CurrencyContext.Provider value={{ currency, currencyInfo, allCurrencies, setCurrency, formatAmount, currencyLabel, loading, coingeckoEnabled }}>
      {children}
    </CurrencyContext.Provider>
  );
}

// reason: useCurrency is the consumer hook for CurrencyProvider, intentionally
// co-located with it. Cost of co-location is full reload (not HMR) when editing
// this file; acceptable for this admin/compliance widget.
// eslint-disable-next-line react-refresh/only-export-components
export function useCurrency() {
  const context = useContext(CurrencyContext);
  if (!context) {
    throw new Error('useCurrency must be used within CurrencyProvider');
  }
  return context;
}
