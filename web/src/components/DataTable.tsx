import type { ReactNode } from 'react'

import { cn } from '@/lib/utils'

interface DataTableShellProps {
  children: ReactNode
  className?: string
  toolbar?: ReactNode
}

export function DataTableShell({ children, className, toolbar }: DataTableShellProps) {
  return (
    <div className={cn('overflow-hidden rounded-lg border bg-card shadow-sm', className)}>
      {toolbar && (
        <div className="flex flex-wrap items-center gap-3 border-b bg-muted/30 px-4 py-3">
          {toolbar}
        </div>
      )}
      {children}
    </div>
  )
}
