import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { Activity, Filter } from 'lucide-react'

import { get } from '@/api/client'
import type { AuditRow } from '@/api/adminTypes'
import { DataTableShell } from '@/components/DataTable'
import { PageHeader } from '@/components/PageHeader'
import { EmptyState, ErrorState, LoadingState } from '@/components/StateViews'
import { StatusBadge, type Tone } from '@/components/StatusBadge'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { absoluteTime, relativeTime } from '@/lib/format'

function actionTone(action: string): Tone {
  const prefix = action.split('.')[0]
  switch (prefix) {
    case 'role':
    case 'user':
      return 'info'
    case 'client':
      return 'warning'
    case 'mfa':
    case 'password':
      return 'primary'
    case 'session':
      return 'neutral'
    default:
      return 'neutral'
  }
}

export function Audit() {
  const [action, setAction] = useState('')
  const [actor, setActor] = useState('')
  const [appliedAction, setAppliedAction] = useState('')
  const [appliedActor, setAppliedActor] = useState('')

  const params = new URLSearchParams()
  if (appliedAction) params.set('action', appliedAction)
  if (appliedActor) params.set('actor', appliedActor)
  params.set('limit', '100')

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['admin-audit', appliedAction, appliedActor],
    queryFn: () => get<AuditRow[]>(`/admin/api/v1/audit?${params.toString()}`),
  })

  function apply() {
    setAppliedAction(action.trim())
    setAppliedActor(actor.trim())
  }
  function reset() {
    setAction('')
    setActor('')
    setAppliedAction('')
    setAppliedActor('')
  }

  const hasFilter = !!(appliedAction || appliedActor)

  return (
    <>
      <PageHeader
        eyebrow="Observability"
        title="Audit log"
        description="Authentication, consent, and administrative events. Showing the most recent 100 matching entries."
      />

      <Card className="mb-6">
        <CardContent className="pt-6">
          <form
            onSubmit={(e) => {
              e.preventDefault()
              apply()
            }}
            className="grid grid-cols-1 items-end gap-3 sm:grid-cols-[1fr_1fr_auto_auto]"
          >
            <div className="space-y-1.5">
              <Label htmlFor="audit-action" className="text-xs uppercase tracking-wider text-muted-foreground">
                Action
              </Label>
              <Input
                id="audit-action"
                value={action}
                onChange={(e) => setAction(e.target.value)}
                placeholder="role.grant, user.create, …"
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="audit-actor" className="text-xs uppercase tracking-wider text-muted-foreground">
                Actor user ID
              </Label>
              <Input
                id="audit-actor"
                value={actor}
                onChange={(e) => setActor(e.target.value)}
                placeholder="uuid"
                className="font-mono"
              />
            </div>
            <Button type="submit">
              <Filter className="h-4 w-4" />
              Apply
            </Button>
            <Button type="button" variant="ghost" onClick={reset} disabled={!hasFilter && !action && !actor}>
              Reset
            </Button>
          </form>
        </CardContent>
      </Card>

      {isLoading && <LoadingState variant="table" rows={6} />}
      {error && <ErrorState message="We couldn't load the audit log." onRetry={() => void refetch()} />}
      {data && data.length === 0 && (
        <EmptyState
          icon={Activity}
          title={hasFilter ? 'No events match these filters' : 'No audit entries yet'}
          description={hasFilter ? 'Try broadening or clearing the filters above.' : "Once activity happens in this tenant, you'll see it here."}
          action={hasFilter ? <Button variant="outline" onClick={reset}>Clear filters</Button> : undefined}
        />
      )}

      {data && data.length > 0 && (
        <DataTableShell>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-40">When</TableHead>
                <TableHead>Action</TableHead>
                <TableHead>Target</TableHead>
                <TableHead>Actor</TableHead>
                <TableHead>IP</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.map((row) => (
                <TableRow key={row.id}>
                  <TableCell>
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <span className="cursor-default text-sm text-foreground">
                          {relativeTime(row.occurred_at)}
                        </span>
                      </TooltipTrigger>
                      <TooltipContent>{absoluteTime(row.occurred_at)}</TooltipContent>
                    </Tooltip>
                  </TableCell>
                  <TableCell>
                    <StatusBadge tone={actionTone(row.action)}>
                      <span className="font-mono text-[11px]">{row.action}</span>
                    </StatusBadge>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-baseline gap-1.5 font-mono text-xs text-muted-foreground">
                      <span>{row.target_type}</span>
                      <span className="text-muted-foreground/50">/</span>
                      <span className="text-foreground">{row.target_id || '—'}</span>
                    </div>
                  </TableCell>
                  <TableCell className="font-mono text-xs text-muted-foreground">
                    {row.actor_user_id || row.actor_client_id || '—'}
                  </TableCell>
                  <TableCell className="font-mono text-xs text-muted-foreground">{row.ip || '—'}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </DataTableShell>
      )}
    </>
  )
}
