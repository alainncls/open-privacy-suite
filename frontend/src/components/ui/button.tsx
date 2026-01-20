import * as React from "react"
import { Slot } from "@radix-ui/react-slot"
import { cva, type VariantProps } from "class-variance-authority"
import { cn } from "@/lib/utils"

const buttonVariants = cva(
  "inline-flex items-center justify-center whitespace-nowrap rounded-lg text-sm font-medium transition-all duration-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary-500/50 focus-visible:ring-offset-2 focus-visible:ring-offset-transparent disabled:pointer-events-none disabled:opacity-50 active:scale-[0.98]",
  {
    variants: {
      variant: {
        default: "bg-primary-600 text-white hover:bg-primary-500 shadow-lg shadow-primary-500/25 hover:shadow-primary-500/40",
        destructive: "bg-red-500/80 text-white hover:bg-red-500 shadow-lg shadow-red-500/25",
        outline: "border border-white/20 bg-white/5 text-white/90 hover:bg-white/10 hover:border-white/30",
        secondary: "bg-white/10 text-white/90 hover:bg-white/15",
        ghost: "text-white/70 hover:bg-white/10 hover:text-white",
        link: "text-primary-400 underline-offset-4 hover:underline hover:text-primary-300",
        glass: "glass-button",
        glassPrimary: "bg-primary-500/20 text-primary-300 border border-primary-500/30 hover:bg-primary-500/30 hover:border-primary-500/50 shadow-lg shadow-primary-500/10",
        glassAccent: "bg-accent-500/20 text-accent-300 border border-accent-500/30 hover:bg-accent-500/30 hover:border-accent-500/50 shadow-lg shadow-accent-500/10",
        success: "bg-green-500/20 text-green-400 border border-green-500/30 hover:bg-green-500/30 hover:border-green-500/50 shadow-lg shadow-green-500/10",
      },
      size: {
        default: "h-10 px-4 py-2",
        sm: "h-9 rounded-lg px-3 text-xs",
        lg: "h-11 rounded-lg px-8",
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
