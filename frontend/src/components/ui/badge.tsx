import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"
import { cn } from "@/lib/utils"

const badgeVariants = cva(
  "inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold transition-all duration-200",
  {
    variants: {
      variant: {
        default: "border-white/20 bg-white/10 text-white/90",
        secondary: "border-white/10 bg-white/5 text-white/70",
        destructive: "badge-glow-error",
        success: "badge-glow-success",
        warning: "badge-glow-warning",
        info: "badge-glow-info",
        primary: "badge-glow-primary",
        accent: "badge-glow-accent",
        outline: "border-white/30 text-white/80 bg-transparent",
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
