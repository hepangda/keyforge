import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { MoreHorizontal, MonitorSmartphone } from 'lucide-react'
import { toast } from 'sonner'

import { get, del } from '@/api/client'
import type { SessionRow } from '@/api/types'
import { DataTableShell } from '@/components/DataTable'
import { PageHeader } from '@/components/PageHeader'
import { ConfirmDialog } from '@/components/ConfirmDialog'
import { EmptyState, ErrorState, LoadingState } from '@/components/StateViews'
import { MfaLevelBadge } from '@/components/StatusBadge'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { absoluteTime, parseUserAgent, relativeTime } from '@/lib/format'

export function Sessions() {
  const qc = useQueryClient()
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['sessions'],
    queryFn: () => get<SessionRow[]>('/portal/api/v1/sessions'),
  })
  const revoke = useMutation({
    mutationFn: (id: string) => del(`/portal/api/v1/sessions/${id}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['sessions'] })
      toast.success('Session revoked')
    },
    onError: (e: Error) => toast.error(e.message),
  })

  return (
    <>
      <PageHeader
        eyebrow="Security"
        title="Active sessions"
        description="Every browser or device currently signed in to your account. Revoke any session you don't recognize."
        actions={
          data && data.length > 0 ? (
            <Badge variant="secondary" className="px-2.5 py-1 text-xs">
              {data.length} active
            </Badge>
          ) : null
        }
      />

      {isLoading && <LoadingState variant="table" rows={4} />}
      {error && (
        <ErrorState message="We couldn't load your sessions." onRetry={() => void refetch()} />
      )}
      {data && data.length === 0 && (
        <EmptyState
          icon={MonitorSmartphone}
          title="No active sessions"
          description="You'll see your signed-in devices here once a session is established."
        />
      )}

      {data && data.length > 0 && (
        <DataTableShell>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="min-w-[180px]">Device</TableHead>
                <TableHead>IP address</TableHead>
                <TableHead>Authentication</TableHead>
                <TableHead>Last seen</TableHead>
                <TableHead>Expires</TableHead>
                <TableHead className="w-12" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.map((s) => {
                const ua = parseUserAgent(s.user_agent)
                return (
                  <TableRow key={s.id}>
                    <TableCell>
                      <div className="flex items-center gap-3">
                        <div className="flex h-8 w-8 items-center justify-center rounded-md bg-secondary text-muted-foreground">
                          <MonitorSmartphone className="h-4 w-4" />
                        </div>
                        <div className="leading-tight">
                          <div className="text-sm font-medium text-foreground">
                            {ua.browser} {ua.os && <span className="text-muted-foreground">· {ua.os}</span>}
                          </div>
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <div className="line-clamp-1 max-w-[260px] cursor-default text-xs text-muted-foreground">
                                {s.user_agent || '—'}
                              </div>
                            </TooltipTrigger>
                            <TooltipContent className="max-w-sm break-all">
                              {s.user_agent || '—'}
                            </TooltipContent>
                          </Tooltip>
                        </div>
                      </div>
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">{s.ip || '—'}</TableCell>
                    <TableCell>
                      <div className="flex flex-col gap-1">
                        <MfaLevelBadge level={s.mfa_level} />
                        {s.amr?.length > 0 && (
                          <div className="text-[11px] uppercase tracking-wide text-muted-foreground">
                            {s.amr.join(' · ')}
                          </div>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <span className="cursor-default text-sm text-foreground">
                            {relativeTime(s.last_seen_at)}
                          </span>
                        </TooltipTrigger>
                        <TooltipContent>{absoluteTime(s.last_seen_at)}</TooltipContent>
                      </Tooltip>
                    </TableCell>
                    <TableCell>
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <span className="cursor-default text-sm text-muted-foreground">
                            {relativeTime(s.expires_at)}
                          </span>
                        </TooltipTrigger>
                        <TooltipContent>{absoluteTime(s.expires_at)}</TooltipContent>
                      </Tooltip>
                    </TableCell>
                    <TableCell className="text-right">
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" size="icon" aria-label="Session actions">
                            <MoreHorizontal />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <ConfirmDialog
                            destructive
                            confirmLabel="Revoke"
                            title="Revoke this session?"
                            description="The signed-in device will be immediately signed out and refresh tokens will be invalidated."
                            loading={revoke.isPending}
                            onConfirm={() => revoke.mutateAsync(s.id)}
                            trigger={
                              <DropdownMenuItem
                                destructive
                                onSelect={(e) => e.preventDefault()}
                              >
                                Revoke session
                              </DropdownMenuItem>
                            }
                          />
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </TableCell>
                  </TableRow>
                )
              })}
            </TableBody>
          </Table>
        </DataTableShell>
      )}
    </>
  )
}
