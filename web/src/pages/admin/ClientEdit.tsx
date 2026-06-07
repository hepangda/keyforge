import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { ArrowLeft, RefreshCw, ShieldAlert, Trash2 } from 'lucide-react'
import { toast } from 'sonner'

import { del, get, postJSON } from '@/api/client'
import type { AdminClient } from '@/api/adminTypes'
import { ConfirmDialog } from '@/components/ConfirmDialog'
import { PageHeader } from '@/components/PageHeader'
import { SecretReveal } from '@/components/SecretReveal'
import { ErrorState, LoadingState } from '@/components/StateViews'
import { BoolBadge, StatusBadge } from '@/components/StatusBadge'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'

export function ClientEdit() {
  const { id } = useParams()
  const qc = useQueryClient()
  const nav = useNavigate()
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['admin-client', id],
    queryFn: () => get<AdminClient>(`/admin/api/v1/clients/${id}`),
    enabled: !!id,
  })
  const remove = useMutation({
    mutationFn: () => del(`/admin/api/v1/clients/${id}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin-clients'] })
      toast.success('Client deleted')
      nav('/admin/clients')
    },
    onError: (e: Error) => toast.error(e.message),
  })
  const rotate = useMutation({
    mutationFn: () => postJSON<{ client_secret: string }>(`/admin/api/v1/clients/${id}/rotate-secret`, {}),
    onSuccess: () => toast.success('New client secret generated'),
    onError: (e: Error) => toast.error(e.message),
  })

  if (isLoading) {
    return (
      <>
        <PageHeader title="Loading client…" />
        <LoadingState variant="form" />
      </>
    )
  }
  if (error || !data) {
    return (
      <>
        <PageHeader title="Client not found" />
        <ErrorState message="The client doesn't exist, or you don't have permission to view it." onRetry={() => void refetch()} />
      </>
    )
  }

  return (
    <>
      <Button asChild variant="ghost" size="sm" className="mb-2 -ml-2">
        <Link to="/admin/clients">
          <ArrowLeft className="h-4 w-4" />
          All clients
        </Link>
      </Button>
      <PageHeader
        eyebrow="OAuth client"
        title={data.name}
        description={
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-foreground">{data.client_id}</span>
            <StatusBadge tone={data.client_type === 'confidential' ? 'info' : 'neutral'}>
              {data.client_type}
            </StatusBadge>
          </div>
        }
      />

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-[1fr_320px]">
        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Configuration</CardTitle>
              <CardDescription>Protocol-level settings for this client.</CardDescription>
            </CardHeader>
            <CardContent>
              <dl className="grid grid-cols-[160px_1fr] gap-y-3 text-sm">
                <Term label="Description">{data.description || <Muted>—</Muted>}</Term>
                <Term label="Grant types">
                  <ChipList items={data.grant_types} />
                </Term>
                <Term label="Scopes">
                  {data.scopes.length ? <ChipList items={data.scopes} /> : <Muted>—</Muted>}
                </Term>
                <Term label="Token endpoint auth">
                  <span className="font-mono text-xs">{data.token_endpoint_auth_method}</span>
                </Term>
                <Term label="PAR required">
                  <BoolBadge on={data.require_par} labelOn="Required" labelOff="Optional" />
                </Term>
                <Term label="DPoP required">
                  <BoolBadge on={data.require_dpop} labelOn="Required" labelOff="Optional" />
                </Term>
                <Term label="DPoP-bound tokens">
                  <BoolBadge on={data.dpop_bound_access_tokens} labelOn="Yes" labelOff="No" />
                </Term>
                <Term label="mTLS-bound tokens">
                  <BoolBadge on={data.tls_client_certificate_bound_access_tokens} labelOn="Yes" labelOff="No" />
                </Term>
              </dl>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Redirect URIs</CardTitle>
              <CardDescription>The authorization endpoint will only redirect to one of these exact URIs.</CardDescription>
            </CardHeader>
            <CardContent>
              {data.redirect_uris.length === 0 ? (
                <Muted>None configured.</Muted>
              ) : (
                <ul className="space-y-2">
                  {data.redirect_uris.map((u) => (
                    <li key={u}>
                      <SecretReveal value={u} />
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>
        </div>

        <div className="space-y-6">
          {data.client_type === 'confidential' && (
            <Card>
              <CardHeader>
                <CardTitle>Credentials</CardTitle>
                <CardDescription>Rotate the client secret. The previous secret stops working immediately.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                {rotate.data?.client_secret ? (
                  <>
                    <Alert variant="warning">
                      <ShieldAlert />
                      <AlertTitle>Save this secret now</AlertTitle>
                      <AlertDescription>It won't be shown again.</AlertDescription>
                    </Alert>
                    <SecretReveal value={rotate.data.client_secret} />
                  </>
                ) : (
                  <p className="text-sm text-muted-foreground">
                    Generates a fresh secret and invalidates the existing one.
                  </p>
                )}
              </CardContent>
              <CardFooter className="border-t bg-muted/30 px-6 py-3">
                <ConfirmDialog
                  title="Rotate client secret?"
                  description="The current secret stops working immediately. Update any downstream services before continuing."
                  confirmLabel="Rotate secret"
                  loading={rotate.isPending}
                  onConfirm={async () => {
                    await rotate.mutateAsync()
                  }}
                  trigger={
                    <Button variant="outline">
                      <RefreshCw className="h-4 w-4" />
                      Rotate secret
                    </Button>
                  }
                />
              </CardFooter>
            </Card>
          )}

          <Card className="border-destructive/30">
            <CardHeader>
              <CardTitle className="text-destructive">Danger zone</CardTitle>
              <CardDescription>All tokens issued for this client are invalidated.</CardDescription>
            </CardHeader>
            <CardFooter className="border-t bg-destructive/[0.03] px-6 py-3">
              <ConfirmDialog
                destructive
                title={`Delete client ${data.client_id}?`}
                description="This permanently removes the client and revokes every token it issued. This cannot be undone."
                confirmLabel="Delete client"
                loading={remove.isPending}
                onConfirm={() => remove.mutateAsync()}
                trigger={
                  <Button variant="destructive">
                    <Trash2 className="h-4 w-4" />
                    Delete client
                  </Button>
                }
              />
            </CardFooter>
          </Card>
        </div>
      </div>
    </>
  )
}

function Term({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <>
      <dt className="text-xs font-medium uppercase tracking-wider text-muted-foreground pt-0.5">{label}</dt>
      <dd className="m-0">{children}</dd>
    </>
  )
}

function ChipList({ items }: { items: string[] }) {
  return (
    <div className="flex flex-wrap gap-1">
      {items.map((i) => (
        <Badge key={i} variant="outline" className="font-mono text-[11px]">
          {i}
        </Badge>
      ))}
    </div>
  )
}

function Muted({ children }: { children: React.ReactNode }) {
  return <span className="text-muted-foreground">{children}</span>
}
