import { useState } from 'react';
import { Search, Filter, X, Calendar } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import type {
  DisclosureFilter,
  DisclosureRequestStatus,
  DisclosureLevel,
} from '@/types/disclosure';
import {
  STATUS_LABELS,
  DISCLOSURE_LEVEL_LABELS,
  ALL_DISCLOSURE_LEVELS,
} from '@/types/disclosure';

interface DisclosureFiltersProps {
  filter: DisclosureFilter;
  onFilterChange: (filter: DisclosureFilter) => void;
  showStatusFilter?: boolean;
  statusOptions?: DisclosureRequestStatus[];
}

const DEFAULT_STATUS_OPTIONS: DisclosureRequestStatus[] = [
  'pending',
  'approved',
  'rejected',
  'revoked',
  'expired',
];

export function DisclosureFilters({
  filter,
  onFilterChange,
  showStatusFilter = true,
  statusOptions = DEFAULT_STATUS_OPTIONS,
}: DisclosureFiltersProps) {
  const [isExpanded, setIsExpanded] = useState(false);

  const updateFilter = (updates: Partial<DisclosureFilter>) => {
    onFilterChange({ ...filter, ...updates });
  };

  const clearFilters = () => {
    onFilterChange({});
  };

  const hasActiveFilters =
    filter.status ||
    filter.requester_did ||
    filter.disclosure_level ||
    filter.date_from ||
    filter.date_to;

  return (
    <div className="space-y-4">
      {/* Main filter bar */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#94A3B8]" />
          <Input
            placeholder="Filter by requester DID..."
            value={filter.requester_did || ''}
            onChange={(e) => updateFilter({ requester_did: e.target.value || undefined })}
            className="pl-10"
          />
        </div>

        <Button
          variant="outline"
          size="sm"
          onClick={() => setIsExpanded(!isExpanded)}
          className={isExpanded ? 'bg-[#F1F5F9]' : ''}
        >
          <Filter className="w-4 h-4 mr-2" />
          Filters
          {hasActiveFilters && (
            <span className="ml-2 w-2 h-2 rounded-full bg-[#8950FA]" />
          )}
        </Button>

        {hasActiveFilters && (
          <Button variant="ghost" size="sm" onClick={clearFilters}>
            <X className="w-4 h-4 mr-2" />
            Clear
          </Button>
        )}
      </div>

      {/* Expanded filters */}
      {isExpanded && (
        <div className="p-4 bg-[#F8FAFC] rounded-lg border border-[#E2E8F0] grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {showStatusFilter && (
            <div>
              <label className="text-xs text-[#6B7280] uppercase tracking-wide mb-1 block">
                Status
              </label>
              <Select
                value={filter.status || 'all'}
                onValueChange={(value) =>
                  updateFilter({ status: value === 'all' ? undefined : (value as DisclosureRequestStatus) })
                }
              >
                <SelectTrigger>
                  <SelectValue placeholder="All statuses" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All statuses</SelectItem>
                  {statusOptions.map((status) => (
                    <SelectItem key={status} value={status}>
                      {STATUS_LABELS[status]}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          )}

          <div>
            <label className="text-xs text-[#6B7280] uppercase tracking-wide mb-1 block">
              Disclosure Level
            </label>
            <Select
              value={filter.disclosure_level || 'all'}
              onValueChange={(value) =>
                updateFilter({ disclosure_level: value === 'all' ? undefined : (value as DisclosureLevel) })
              }
            >
              <SelectTrigger>
                <SelectValue placeholder="All levels" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All levels</SelectItem>
                {ALL_DISCLOSURE_LEVELS.map((level) => (
                  <SelectItem key={level} value={level}>
                    {DISCLOSURE_LEVEL_LABELS[level]}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div>
            <label className="text-xs text-[#6B7280] uppercase tracking-wide mb-1 block">
              <Calendar className="w-3 h-3 inline mr-1" />
              From Date
            </label>
            <Input
              type="date"
              value={filter.date_from?.split('T')[0] || ''}
              onChange={(e) =>
                updateFilter({
                  date_from: e.target.value ? new Date(e.target.value).toISOString() : undefined,
                })
              }
            />
          </div>

          <div>
            <label className="text-xs text-[#6B7280] uppercase tracking-wide mb-1 block">
              <Calendar className="w-3 h-3 inline mr-1" />
              To Date
            </label>
            <Input
              type="date"
              value={filter.date_to?.split('T')[0] || ''}
              onChange={(e) =>
                updateFilter({
                  date_to: e.target.value ? new Date(e.target.value).toISOString() : undefined,
                })
              }
            />
          </div>
        </div>
      )}
    </div>
  );
}

export default DisclosureFilters;
