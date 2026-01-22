import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"
import { cn } from "@/lib/utils"

const inputVariants = cva(
  "flex w-full text-sm transition-all duration-200 file:border-0 file:bg-transparent file:text-sm file:font-medium disabled:cursor-not-allowed disabled:opacity-50 disabled:bg-[#F1F5F9]",
  {
    variants: {
      variant: {
        default: "h-10 rounded-lg border border-[#CBD5E1] bg-white px-3 py-2 text-[#0F0F0F] placeholder:text-[#6B7280] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#8950FA]/20 focus-visible:border-[#8950FA]",
        ghost: "h-10 rounded-lg border-0 bg-transparent px-3 py-2 text-[#0F0F0F] placeholder:text-[#6B7280] focus-visible:outline-none focus-visible:bg-[#F1F5F9]",
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
