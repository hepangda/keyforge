import { useQuery } from '@tanstack/react-query'
import { LogOut, ShieldCheck, UserRound } from 'lucide-react'

import { Avatar, AvatarFallback } from '@/components/ui/avatar'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Skeleton } from '@/components/ui/skeleton'
import { get } from '@/api/client'
import type { UserProfile } from '@/api/types'
import { clearTokens } from '@/auth/oidc'

function initials(email: string, displayName: string): string {
  const source = displayName?.trim() || email
  const parts = source.split(/[\s@.]+/).filter(Boolean)
  if (!parts.length) return '?'
  if (parts.length === 1) return parts[0]!.slice(0, 2).toUpperCase()
  return (parts[0]![0]! + parts[1]![0]!).toUpperCase()
}

export function UserMenu({ section }: { section: 'portal' | 'admin' }) {
  const { data, isLoading } = useQuery({
    queryKey: ['me'],
    queryFn: () => get<UserProfile>('/portal/api/v1/me'),
    staleTime: 5 * 60_000,
  })

  if (isLoading || !data) {
    return (
      <div className="flex items-center gap-3 rounded-md border border-sidebar-border/60 bg-sidebar-accent/40 px-3 py-2.5">
        <Skeleton className="h-8 w-8 rounded-full bg-sidebar-accent" />
        <div className="flex flex-1 flex-col gap-1.5">
          <Skeleton className="h-3 w-24 bg-sidebar-accent" />
          <Skeleton className="h-2.5 w-32 bg-sidebar-accent" />
        </div>
      </div>
    )
  }

  const switchHref = section === 'portal' ? '/admin' : '/portal'
  const switchLabel = section === 'portal' ? 'Switch to admin' : 'Switch to portal'
  const SwitchIcon = section === 'portal' ? ShieldCheck : UserRound

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button
          type="button"
          className="flex w-full items-center gap-3 rounded-md border border-sidebar-border/60 bg-sidebar-accent/40 px-3 py-2.5 text-left transition-colors hover:bg-sidebar-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-sidebar"
        >
          <Avatar className="h-8 w-8">
            <AvatarFallback className="bg-primary/20 text-primary-foreground">
              {initials(data.email, data.display_name)}
            </AvatarFallback>
          </Avatar>
          <div className="flex min-w-0 flex-1 flex-col">
            <span className="truncate text-sm font-medium text-sidebar-foreground">
              {data.display_name || data.email.split('@')[0]}
            </span>
            <span className="truncate text-xs text-sidebar-muted">{data.email}</span>
          </div>
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent side="top" align="end" className="w-56">
        <DropdownMenuLabel>Signed in</DropdownMenuLabel>
        <DropdownMenuItem asChild>
          <a href={switchHref}>
            <SwitchIcon className="h-4 w-4" />
            {switchLabel}
          </a>
        </DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem
          destructive
          onSelect={() => {
            clearTokens()
            window.location.assign('/portal')
          }}
        >
          <LogOut className="h-4 w-4" />
          Sign out
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

export { Button as _Button }
