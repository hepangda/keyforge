import type { SVGProps } from 'react'

import { cn } from '@/lib/utils'

interface BrandMarkProps extends SVGProps<SVGSVGElement> {
  size?: number
}

export function BrandMark({ size = 28, className, ...props }: BrandMarkProps) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 32 32"
      width={size}
      height={size}
      className={cn('shrink-0', className)}
      role="img"
      aria-label="keyforge"
      {...props}
    >
      <rect width="32" height="32" rx="7" fill="hsl(var(--sidebar))" />
      <path
        d="M16 6.5l8 3v6.2c0 4.6-3.2 8.7-8 10-4.8-1.3-8-5.4-8-10V9.5l8-3z"
        stroke="hsl(var(--primary))"
        strokeWidth={1.8}
        strokeLinejoin="round"
        fill="none"
      />
      <circle cx="16" cy="14.5" r="2.6" fill="hsl(var(--accent))" />
      <rect x="15" y="16" width="2" height="5.2" rx="0.6" fill="hsl(var(--accent))" />
      <rect x="15" y="18.2" width="3.4" height="1.2" rx="0.4" fill="hsl(var(--accent))" />
    </svg>
  )
}

export function BrandWordmark({ className }: { className?: string }) {
  return (
    <div className={cn('flex items-center gap-2.5', className)}>
      <BrandMark size={28} />
      <div className="leading-tight">
        <div className="text-sm font-semibold tracking-tight text-sidebar-foreground">keyforge</div>
        <div className="text-[10px] font-medium uppercase tracking-[0.14em] text-sidebar-muted">
          Identity platform
        </div>
      </div>
    </div>
  )
}
