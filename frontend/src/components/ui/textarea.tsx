import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"
import { cn } from "@/lib/utils"

const textareaVariants = cva(
  "flex min-h-[80px] w-full text-sm transition-all duration-200 disabled:cursor-not-allowed disabled:opacity-50 disabled:bg-[#F1F5F9]",
  {
    variants: {
      variant: {
        default: "rounded-lg border border-[#CBD5E1] bg-white px-3 py-2 text-[#0F0F0F] placeholder:text-[#6B7280] focus:outline-none focus:ring-2 focus:ring-[#8950FA]/20 focus:border-[#8950FA] resize-none",
        code: "rounded-lg border border-[#E2E8F0] bg-[#F1F5F9] px-4 py-3 font-mono text-sm text-[#374151] placeholder:text-[#6B7280] focus:outline-none focus:ring-2 focus:ring-[#8950FA]/20 focus:border-[#8950FA] resize-none",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  }
)

export interface TextareaProps
  extends React.TextareaHTMLAttributes<HTMLTextAreaElement>,
    VariantProps<typeof textareaVariants> {}

const Textarea = React.forwardRef<HTMLTextAreaElement, TextareaProps>(
  ({ className, variant, ...props }, ref) => {
    return (
      <textarea
        className={cn(textareaVariants({ variant, className }))}
        ref={ref}
        {...props}
      />
    )
  }
)
Textarea.displayName = "Textarea"

export { Textarea, textareaVariants }
