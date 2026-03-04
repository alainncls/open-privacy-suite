import { useState } from 'react';
import { Loader2 } from 'lucide-react';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { useCurrency } from './CurrencyContext';

export default function CurrencySelector() {
  const { currency, allCurrencies, setCurrency, currencyInfo, loading } = useCurrency();
  const [switching, setSwitching] = useState(false);

  const handleChange = async (code: string) => {
    if (code === currency) return;
    setSwitching(true);
    try {
      await setCurrency(code);
    } finally {
      setSwitching(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center gap-2 text-[#94A3B8]">
        <Loader2 className="w-4 h-4 animate-spin" />
        <span className="text-sm">Currency...</span>
      </div>
    );
  }

  return (
    <div className="flex items-center gap-2">
      <span className="text-sm text-[#6B7280]">Currency:</span>
      <Select value={currency} onValueChange={handleChange} disabled={switching}>
        <SelectTrigger className="w-[140px] h-8 text-sm" data-testid="currency-selector">
          <SelectValue>
            {switching ? (
              <span className="flex items-center gap-1.5">
                <Loader2 className="w-3 h-3 animate-spin" />
                <span>Switching...</span>
              </span>
            ) : (
              <span>{currencyInfo?.symbol} {currency.toUpperCase()}</span>
            )}
          </SelectValue>
        </SelectTrigger>
        <SelectContent>
          {allCurrencies.map((c) => (
            <SelectItem key={c.code} value={c.code}>
              <span className="flex items-center gap-2">
                <span className="w-6 text-center font-medium">{c.symbol}</span>
                <span>{c.code.toUpperCase()}</span>
                <span className="text-[#94A3B8] text-xs">({c.name})</span>
              </span>
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  );
}
