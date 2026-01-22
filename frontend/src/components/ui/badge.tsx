import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"
import { cn } from "@/lib/utils"

const badgeVariants = cva(
  "inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold transition-all duration-200",
  {
    variants: {
      variant: {
        default: "border-[#E2E8F0] bg-[#F1F5F9] text-[#374151]",
        secondary: "border-[#E2E8F0] bg-white text-[#6B7280]",
        destructive: "border-transparent bg-[#FEE2E2] text-[#991B1B]",
        success: "border-transparent bg-[#DCFCE7] text-[#166534]",
        warning: "border-transparent bg-[#FEF9C3] text-[#854D0E]",
        info: "border-transparent bg-[#F5F3FF] text-[#8950FA]",
        primary: "border-transparent bg-[#F5F3FF] text-[#8950FA]",
        outline: "border-[#CBD5E1] text-[#374151] bg-transparent",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  }
)

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return (
    <div className={cn(badgeVariants({ variant }), className)} {...props} />
  )
}

export { Badge, badgeVariants }
