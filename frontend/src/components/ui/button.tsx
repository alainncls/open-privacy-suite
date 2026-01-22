import * as React from "react"
import { Slot } from "@radix-ui/react-slot"
import { cva, type VariantProps } from "class-variance-authority"
import { cn } from "@/lib/utils"

const buttonVariants = cva(
  "inline-flex items-center justify-center whitespace-nowrap rounded-full text-sm font-medium transition-all duration-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#8950FA]/40 focus-visible:ring-offset-2 focus-visible:ring-offset-white disabled:pointer-events-none disabled:opacity-50 active:scale-[0.98]",
  {
    variants: {
      variant: {
        default: "bg-[#8950FA] text-white hover:bg-[#6B3DD4] hover:shadow-primary",
        destructive: "bg-[#FEE2E2] text-[#991B1B] hover:bg-[#FECACA]",
        outline: "border border-[#CBD5E1] bg-white text-[#0F0F0F] hover:bg-[#F5F3FF] hover:border-[#8950FA]",
        secondary: "bg-white text-[#0F0F0F] border border-[#CBD5E1] hover:bg-[#F5F3FF] hover:border-[#8950FA]",
        ghost: "text-[#8950FA] hover:bg-[#F5F3FF]",
        link: "text-[#8950FA] underline-offset-4 hover:underline hover:text-[#6B3DD4]",
        success: "bg-[#DCFCE7] text-[#166534] hover:bg-[#BBF7D0]",
      },
      size: {
        default: "h-10 px-6 py-2",
        sm: "h-9 rounded-full px-4 text-xs",
        lg: "h-11 rounded-full px-8",
        icon: "h-10 w-10",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  }
)

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, ...props }, ref) => {
    const Comp = asChild ? Slot : "button"
    return (
      <Comp
        className={cn(buttonVariants({ variant, size, className }))}
        ref={ref}
        {...props}
      />
    )
  }
)
Button.displayName = "Button"

export { Button, buttonVariants }
