import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { KeyRound } from 'lucide-react'
import { toast } from 'sonner'

import { del, get } from '@/api/client'
import type { ConsentRow } from '@/api/types'
import { ConfirmDialog } from '@/components/ConfirmDialog'
import { PageHeader } from '@/components/PageHeader'
import { EmptyState, ErrorState, LoadingState } from '@/components/StateViews'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardFooter, CardHeader } from '@/components/ui/card'
import { absoluteTime, relativeTime } from '@/lib/format'

export function Consents() {
  const qc = useQueryClient()
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['consents'],
    queryFn: () => get<ConsentRow[]>('/portal/api/v1/consents'),
  })
  const revoke = useMutation({
    mutationFn: (id: string) => del(`/portal/api/v1/consents/${id}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['consents'] })
      toast.success('Access revoked')
    },
    onError: (e: Error) => toast.error(e.message),
  })

  return (
    <>
      <PageHeader
        eyebrow="Security"
        title="Authorized applications"
        description="Apps that hold OAuth tokens on your behalf. Revoking access blocks the app until you sign in again."
      />

      {isLoading && <LoadingState variant="cards" rows={4} />}
      {error && <ErrorState message="We couldn't load your consent grants." onRetry={() => void refetch()} />}
      {data && data.length === 0 && (
        <EmptyState
          icon={KeyRound}
          title="No third-party access"
          description="When you grant an app access to your account, it'll appear here so you can review and revoke."
        />
      )}

      {data && data.length > 0 && (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          {data.map((c) => (
            <Card key={c.id} className="flex flex-col">
              <CardHeader className="flex-row items-start justify-between gap-4 space-y-0">
                <div className="flex items-center gap-3">
                  <div className="flex h-10 w-10 items-center justify-center rounded-md bg-primary/10 text-primary">
                    <KeyRound className="h-5 w-5" />
                  </div>
                  <div className="leading-tight">
                    <div className="text-sm font-semibold text-foreground">{c.client_id}</div>
                    <div title={absoluteTime(c.granted_at)} className="text-xs text-muted-foreground">
                      Granted {relativeTime(c.granted_at)}
                    </div>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="flex-1">
                <div className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                  Scopes
                </div>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {c.scopes.map((s) => (
                    <Badge key={s} variant="outline" className="font-mono text-[11px]">
                      {s}
                    </Badge>
                  ))}
                </div>
              </CardContent>
              <CardFooter className="justify-end border-t bg-muted/30 px-6 py-3">
                <ConfirmDialog
                  destructive
                  confirmLabel="Revoke access"
                  title={`Revoke access for ${c.client_id}?`}
                  description="The app will no longer be able to use your account until you grant access again."
                  loading={revoke.isPending}
                  onConfirm={() => revoke.mutateAsync(c.id)}
                  trigger={
                    <Button variant="ghost" size="sm" className="text-destructive hover:bg-destructive/10 hover:text-destructive">
                      Revoke access
                    </Button>
                  }
                />
              </CardFooter>
            </Card>
          ))}
        </div>
      )}
    </>
  )
}
