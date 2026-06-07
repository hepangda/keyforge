import type { ReactNode } from 'react'

import { TooltipProvider } from '@/components/ui/tooltip'
import { Sidebar } from './Sidebar'
import { Topbar } from './Topbar'

interface AppShellProps {
  section: 'portal' | 'admin'
  children: ReactNode
  topbarActions?: ReactNode
}

export function AppShell({ section, children, topbarActions }: AppShellProps) {
  return (
    <TooltipProvider delayDuration={200}>
      <div className="grid h-screen grid-cols-[260px_minmax(0,1fr)] bg-surface">
        <Sidebar section={section} />
        <div className="flex h-screen flex-col overflow-hidden">
          <Topbar section={section}>{topbarActions}</Topbar>
          <main className="flex-1 overflow-y-auto">
            <div className="mx-auto w-full max-w-6xl px-8 py-8">{children}</div>
          </main>
        </div>
      </div>
    </TooltipProvider>
  )
}
