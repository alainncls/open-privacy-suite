import { useState } from 'react';
import { Loader2 } from 'lucide-react';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import { useCurrency, CurrencyConflictError } from './CurrencyContext';

export default function CurrencySelector() {
  const { currency, allCurrencies, setCurrency, currencyInfo, loading } = useCurrency();
  const [switching, setSwitching] = useState(false);
  const [conflict, setConflict] = useState<CurrencyConflictError | null>(null);

  const handleChange = async (code: string) => {
    if (code === currency) return;
    setSwitching(true);
    try {
      await setCurrency(code);
    } catch (err) {
      if (err instanceof CurrencyConflictError) {
        setConflict(err);
      }
    } finally {
      setSwitching(false);
    }
  };

  const handleForceSwitch = async () => {
    if (!conflict) return;
    setSwitching(true);
    try {
      await setCurrency(conflict.conflict.currency, true);
    } finally {
      setSwitching(false);
      setConflict(null);
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

  const conflictDescription = conflict
    ? `${conflict.conflict.affected_tokens.length} manual token price(s) do not have a price set for ${conflict.conflict.currency.toUpperCase()}. Affected: ${conflict.conflict.affected_tokens.map(t => t.symbol).join(', ')}. These tokens will BLOCK ALL TRANSACTIONS until prices are configured for this currency.`
    : '';

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

      <ConfirmDialog
        open={!!conflict}
        onOpenChange={(open) => { if (!open) setConflict(null); }}
        title="Currency Switch Warning"
        description={conflictDescription}
        onConfirm={handleForceSwitch}
        confirmLabel="Switch Anyway"
        variant="warning"
      />
    </div>
  );
}
