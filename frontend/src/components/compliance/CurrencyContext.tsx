import { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { complianceApi } from '@/api/compliance';
import type { CurrencyInfo } from '@/types/compliance';

interface CurrencyContextType {
  currency: string;
  currencyInfo: CurrencyInfo | null;
  allCurrencies: CurrencyInfo[];
  setCurrency: (code: string) => Promise<void>;
  formatAmount: (amount: number) => string;
  currencyLabel: string; // e.g. "USD", "EUR"
  loading: boolean;
  coingeckoEnabled: boolean;
  externalRatesApiEnabled: boolean;
}

const CurrencyContext = createContext<CurrencyContextType | null>(null);

const DEFAULT_CURRENCY_INFO: CurrencyInfo = { code: 'usd', name: 'US Dollar', symbol: '$' };

export function CurrencyProvider({ children }: { children: React.ReactNode }) {
  const [currency, setCurrencyState] = useState('usd');
  const [allCurrencies, setAllCurrencies] = useState<CurrencyInfo[]>([DEFAULT_CURRENCY_INFO]);
  const [loading, setLoading] = useState(true);
  const [coingeckoEnabled, setCoingeckoEnabled] = useState(true);
  const [externalRatesApiEnabled, setExternalRatesApiEnabled] = useState(false);

  const loadCurrency = useCallback(async () => {
    try {
      const response = await complianceApi.currency.get();
      const data = response.data;
      setCurrencyState(data.currency || 'usd');
      if (data.all_currencies?.length) {
        setAllCurrencies(data.all_currencies);
      }
      setCoingeckoEnabled(data.coingecko_enabled ?? true);
      setExternalRatesApiEnabled(data.external_rates_api_enabled ?? false);
    } catch {
      // Fallback to USD
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadCurrency();
  }, [loadCurrency]);

  const setCurrency = useCallback(async (code: string) => {
    await complianceApi.currency.set(code);
    setCurrencyState(code);
  }, []);

  const currencyInfo = allCurrencies.find(c => c.code === currency) || DEFAULT_CURRENCY_INFO;

  const formatAmount = useCallback((amount: number) => {
    const info = allCurrencies.find(c => c.code === currency) || DEFAULT_CURRENCY_INFO;
    return `${info.symbol}${amount.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
  }, [currency, allCurrencies]);

  const currencyLabel = currency.toUpperCase();

  return (
    <CurrencyContext.Provider value={{ currency, currencyInfo, allCurrencies, setCurrency, formatAmount, currencyLabel, loading, coingeckoEnabled, externalRatesApiEnabled }}>
      {children}
    </CurrencyContext.Provider>
  );
}

export function useCurrency() {
  const context = useContext(CurrencyContext);
  if (!context) {
    throw new Error('useCurrency must be used within CurrencyProvider');
  }
  return context;
}
