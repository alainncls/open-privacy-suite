import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"
import { cn } from "@/lib/utils"

const inputVariants = cva(
  "flex w-full text-sm transition-all duration-200 file:border-0 file:bg-transparent file:text-sm file:font-medium disabled:cursor-not-allowed disabled:opacity-50",
  {
    variants: {
      variant: {
        default: "h-10 rounded-lg border border-white/20 bg-white/5 px-3 py-2 text-white/90 placeholder:text-white/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary-500/50 focus-visible:border-primary-500/50 hover:bg-white/10 hover:border-white/30",
        glass: "glass-input",
        glassSolid: "h-10 rounded-lg border border-white/20 bg-primary-950/60 backdrop-blur-sm px-3 py-2 text-white/90 placeholder:text-white/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary-500/50 focus-visible:border-primary-500/50",
        ghost: "h-10 rounded-lg border-0 bg-transparent px-3 py-2 text-white/90 placeholder:text-white/50 focus-visible:outline-none focus-visible:bg-white/5",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  }
)

export interface InputProps
  extends React.InputHTMLAttributes<HTMLInputElement>,
    VariantProps<typeof inputVariants> {}

const Input = React.forwardRef<HTMLInputElement, InputProps>(
  ({ className, variant, type, ...props }, ref) => {
    return (
      <input
        type={type}
        className={cn(inputVariants({ variant, className }))}
        ref={ref}
        {...props}
      />
    )
  }
)
Input.displayName = "Input"

export { Input, inputVariants }
