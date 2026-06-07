import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useState } from 'react'
import {
  Fingerprint,
  KeySquare,
  PlusCircle,
  RefreshCw,
  ShieldAlert,
  Smartphone,
  Trash2,
} from 'lucide-react'
import { toast } from 'sonner'
import QRCode from 'qrcode'

import { del, get, postJSON } from '@/api/client'
import type { MFAStatus, RecoveryCodesResp, TOTPEnrollBeginResp } from '@/api/types'
import { runRegisterCeremony, type PasskeyRow, type RegisterBeginResp } from '@/auth/webauthn'
import { ConfirmDialog } from '@/components/ConfirmDialog'
import { PageHeader } from '@/components/PageHeader'
import { SecretReveal } from '@/components/SecretReveal'
import { EmptyState, ErrorState, LoadingState } from '@/components/StateViews'
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
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { relativeTime } from '@/lib/format'

export function Mfa() {
  const qc = useQueryClient()
  const status = useQuery({
    queryKey: ['mfa-status'],
    queryFn: () => get<MFAStatus>('/portal/api/v1/mfa'),
  })

  if (status.isLoading) {
    return (
      <>
        <PageHeader eyebrow="Security" title="Multi-factor authentication" />
        <LoadingState variant="cards" rows={2} />
      </>
    )
  }
  if (status.error || !status.data) {
    return (
      <>
        <PageHeader eyebrow="Security" title="Multi-factor authentication" />
        <ErrorState message="We couldn't load your MFA status." onRetry={() => void status.refetch()} />
      </>
    )
  }

  const refresh = () => qc.invalidateQueries({ queryKey: ['mfa-status'] })
  const s = status.data
  const enrolledCount = (s.totp ? 1 : 0) + (s.webauthn ? 1 : 0)

  return (
    <>
      <PageHeader
        eyebrow="Security"
        title="Multi-factor authentication"
        description="Add multiple factors so a compromised password is not enough to take over your account."
      />

      <div className="mb-6 grid grid-cols-1 gap-4 md:grid-cols-3">
        <StatTile label="Passkeys" enabled={s.webauthn} icon={Fingerprint} />
        <StatTile label="Authenticator app" enabled={s.totp} icon={Smartphone} />
        <StatTile
          label="Recovery codes"
          enabled={s.recovery_codes_remaining > 0}
          icon={KeySquare}
          caption={`${s.recovery_codes_remaining} remaining`}
        />
      </div>

      {enrolledCount === 0 && (
        <Alert variant="warning" className="mb-6">
          <ShieldAlert />
          <AlertTitle>You have no second factor enrolled</AlertTitle>
          <AlertDescription>
            Add at least one passkey or authenticator app. Recovery codes alone aren't a second factor —
            they're a backup for the day your other factor is unavailable.
          </AlertDescription>
        </Alert>
      )}

      <Tabs defaultValue="passkeys" className="w-full">
        <TabsList>
          <TabsTrigger value="passkeys">Passkeys</TabsTrigger>
          <TabsTrigger value="totp">Authenticator app</TabsTrigger>
          <TabsTrigger value="recovery">Recovery codes</TabsTrigger>
        </TabsList>
        <TabsContent value="passkeys">
          <PasskeysCard onChange={refresh} />
        </TabsContent>
        <TabsContent value="totp">
          <TOTPCard enrolled={s.totp} onChange={refresh} />
        </TabsContent>
        <TabsContent value="recovery">
          <RecoveryCard remaining={s.recovery_codes_remaining} onChange={refresh} />
        </TabsContent>
      </Tabs>
    </>
  )
}

function StatTile({
  label,
  enabled,
  icon: Icon,
  caption,
}: {
  label: string
  enabled: boolean
  icon: typeof Fingerprint
  caption?: string
}) {
  return (
    <div className="rounded-lg border bg-card p-4 shadow-sm">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <div className="flex h-8 w-8 items-center justify-center rounded-md bg-secondary text-foreground">
            <Icon className="h-4 w-4" />
          </div>
          <div className="text-sm font-medium">{label}</div>
        </div>
        <BoolBadge on={enabled} labelOn="Active" labelOff="Off" />
      </div>
      {caption && <div className="mt-2 text-xs text-muted-foreground">{caption}</div>}
    </div>
  )
}

function PasskeysCard({ onChange }: { onChange: () => void }) {
  const qc = useQueryClient()
  const list = useQuery({
    queryKey: ['mfa-webauthn'],
    queryFn: () => get<PasskeyRow[]>('/portal/api/v1/mfa/webauthn'),
  })
  const [nickname, setNickname] = useState('')
  const [err, setErr] = useState<string | null>(null)

  const enroll = useMutation({
    mutationFn: async () => {
      setErr(null)
      const begin = await postJSON<RegisterBeginResp>('/portal/api/v1/mfa/webauthn/register/begin', {})
      const credential = await runRegisterCeremony(begin)
      await postJSON<void>('/portal/api/v1/mfa/webauthn/register/finish', {
        challenge_id: begin.challenge_id,
        nickname,
        credential,
      })
    },
    onSuccess: () => {
      setNickname('')
      qc.invalidateQueries({ queryKey: ['mfa-webauthn'] })
      onChange()
      toast.success('Passkey added')
    },
    onError: (e: Error) => setErr(e.message),
  })

  const remove = useMutation({
    mutationFn: (id: string) => del(`/portal/api/v1/mfa/webauthn/${id}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['mfa-webauthn'] })
      onChange()
      toast.success('Passkey removed')
    },
    onError: (e: Error) => toast.error(e.message),
  })

  const supported = typeof window !== 'undefined' && !!window.PublicKeyCredential

  return (
    <Card>
      <CardHeader>
        <CardTitle>Passkeys</CardTitle>
        <CardDescription>
          Use a fingerprint, face scan, security key, or device passcode in place of a password.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {!supported && (
          <Alert variant="warning">
            <ShieldAlert />
            <AlertDescription>This browser doesn't support WebAuthn.</AlertDescription>
          </Alert>
        )}

        {list.isLoading && <LoadingState variant="table" rows={2} />}

        {list.data && list.data.length > 0 && (
          <ul className="divide-y rounded-md border">
            {list.data.map((p) => (
              <li key={p.id} className="flex items-center justify-between gap-4 px-4 py-3">
                <div className="flex items-center gap-3">
                  <div className="flex h-9 w-9 items-center justify-center rounded-md bg-primary/10 text-primary">
                    <Fingerprint className="h-4 w-4" />
                  </div>
                  <div className="leading-tight">
                    <div className="text-sm font-medium text-foreground">
                      {p.nickname || 'Unnamed passkey'}
                    </div>
                    <div className="text-xs text-muted-foreground">
                      Added {relativeTime(p.created_at)}
                      {p.transports?.length ? ` · ${p.transports.join(', ')}` : ''}
                    </div>
                  </div>
                </div>
                <ConfirmDialog
                  destructive
                  title="Remove this passkey?"
                  description="You'll no longer be able to use it to sign in or to satisfy MFA challenges."
                  confirmLabel="Remove"
                  loading={remove.isPending}
                  onConfirm={() => remove.mutateAsync(p.id)}
                  trigger={
                    <Button variant="ghost" size="sm" className="text-destructive hover:bg-destructive/10 hover:text-destructive">
                      <Trash2 className="h-4 w-4" />
                      Remove
                    </Button>
                  }
                />
              </li>
            ))}
          </ul>
        )}

        {list.data && list.data.length === 0 && supported && (
          <EmptyState
            icon={Fingerprint}
            title="No passkeys yet"
            description="Add one to sign in without typing a code."
          />
        )}

        {supported && (
          <div className="space-y-3 rounded-md border bg-surface p-4">
            <div className="text-sm font-medium">Add a new passkey</div>
            <div className="flex flex-col gap-2 sm:flex-row sm:items-end">
              <div className="flex-1 space-y-1.5">
                <Label htmlFor="passkey-nickname">Nickname (optional)</Label>
                <Input
                  id="passkey-nickname"
                  value={nickname}
                  onChange={(e) => setNickname(e.target.value)}
                  placeholder="MacBook Pro"
                />
              </div>
              <Button type="button" onClick={() => enroll.mutate()} disabled={enroll.isPending}>
                <PlusCircle className="h-4 w-4" />
                {enroll.isPending ? 'Touch your authenticator…' : 'Add a passkey'}
              </Button>
            </div>
            {err && (
              <Alert variant="destructive">
                <ShieldAlert />
                <AlertDescription>{err}</AlertDescription>
              </Alert>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  )
}

function TOTPCard({ enrolled, onChange }: { enrolled: boolean; onChange: () => void }) {
  const qc = useQueryClient()
  const [enroll, setEnroll] = useState<TOTPEnrollBeginResp | null>(null)
  const [code, setCode] = useState('')
  const [confirmError, setConfirmError] = useState<string | null>(null)
  const [qrSrc, setQrSrc] = useState<string | null>(null)

  useEffect(() => {
    if (!enroll) {
      setQrSrc(null)
      return
    }
    let cancelled = false
    QRCode.toDataURL(enroll.otpauth_url, { margin: 1, width: 220 })
      .then((url) => {
        if (!cancelled) setQrSrc(url)
      })
      .catch(() => {
        if (!cancelled) setQrSrc(null)
      })
    return () => {
      cancelled = true
    }
  }, [enroll])

  const begin = useMutation({
    mutationFn: () => postJSON<TOTPEnrollBeginResp>('/portal/api/v1/mfa/totp/enroll/begin', {}),
    onSuccess: (r) => setEnroll(r),
    onError: (e: Error) => toast.error(e.message),
  })
  const confirm = useMutation({
    mutationFn: () => postJSON<void>('/portal/api/v1/mfa/totp/enroll/confirm', { code }),
    onSuccess: () => {
      setEnroll(null)
      setCode('')
      setConfirmError(null)
      qc.invalidateQueries({ queryKey: ['mfa-status'] })
      onChange()
      toast.success('Authenticator app enabled')
    },
    onError: (e: Error) => setConfirmError(e.message),
  })
  const remove = useMutation({
    mutationFn: () => del('/portal/api/v1/mfa/totp'),
    onSuccess: () => {
      onChange()
      toast.success('Authenticator app removed')
    },
    onError: (e: Error) => toast.error(e.message),
  })

  return (
    <Card>
      <CardHeader>
        <CardTitle>Authenticator app</CardTitle>
        <CardDescription>
          Time-based one-time passwords from any RFC 6238 app (1Password, Authy, Google Authenticator).
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {enrolled && !enroll && (
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-md border bg-success/5 px-4 py-3">
            <div className="flex items-center gap-2">
              <StatusBadge tone="success">Enabled</StatusBadge>
              <span className="text-sm text-muted-foreground">
                You'll be prompted for a 6-digit code at sign-in.
              </span>
            </div>
            <ConfirmDialog
              destructive
              title="Remove authenticator app?"
              description="You'll lose the ability to satisfy MFA with a TOTP code. Add a passkey or new TOTP first."
              confirmLabel="Remove"
              loading={remove.isPending}
              onConfirm={() => remove.mutateAsync()}
              trigger={
                <Button variant="ghost" size="sm" className="text-destructive hover:bg-destructive/10 hover:text-destructive">
                  Remove
                </Button>
              }
            />
          </div>
        )}
        {!enrolled && !enroll && (
          <EmptyState
            icon={Smartphone}
            title="Authenticator app not set up"
            description="Set up a TOTP app for a backup second factor."
            action={
              <Button type="button" onClick={() => begin.mutate()} disabled={begin.isPending}>
                {begin.isPending ? 'Setting up…' : 'Enable authenticator app'}
              </Button>
            }
          />
        )}
        {enroll && (
          <div className="space-y-4 rounded-md border bg-surface p-4">
            <div className="grid grid-cols-1 gap-4 md:grid-cols-[220px_1fr] md:items-start">
              <div className="flex aspect-square w-[220px] items-center justify-center rounded-md border bg-white p-3">
                {qrSrc ? (
                  <img src={qrSrc} alt="TOTP enrollment QR code" className="h-full w-full" />
                ) : (
                  <div className="text-xs text-muted-foreground">Generating QR…</div>
                )}
              </div>
              <div className="space-y-3">
                <div>
                  <div className="text-sm font-medium">1. Scan the QR code</div>
                  <p className="mt-1 text-sm text-muted-foreground">
                    Open your authenticator app and scan the code. Or enter the secret manually:
                  </p>
                  <div className="mt-2">
                    <SecretReveal value={enroll.secret} />
                  </div>
                </div>
                <div>
                  <div className="text-sm font-medium">2. Enter the 6-digit code</div>
                  <div className="mt-2 flex flex-col gap-2 sm:flex-row sm:items-center">
                    <Input
                      value={code}
                      onChange={(e) => setCode(e.target.value)}
                      inputMode="numeric"
                      placeholder="123456"
                      className="font-mono tracking-[0.4em]"
                      maxLength={8}
                    />
                    <Button
                      type="button"
                      onClick={() => confirm.mutate()}
                      disabled={!code || confirm.isPending}
                    >
                      {confirm.isPending ? 'Confirming…' : 'Confirm'}
                    </Button>
                  </div>
                </div>
                {confirmError && (
                  <Alert variant="destructive">
                    <ShieldAlert />
                    <AlertDescription>{confirmError}</AlertDescription>
                  </Alert>
                )}
              </div>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

function RecoveryCard({ remaining, onChange }: { remaining: number; onChange: () => void }) {
  const [codes, setCodes] = useState<string[] | null>(null)
  const regenerate = useMutation({
    mutationFn: () => postJSON<RecoveryCodesResp>('/portal/api/v1/mfa/recovery/regenerate', {}),
    onSuccess: (r) => {
      setCodes(r.codes)
      onChange()
    },
    onError: (e: Error) => toast.error(e.message),
  })
  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle>Recovery codes</CardTitle>
          <CardDescription>
            Single-use backup codes for when your passkey or authenticator app isn't available.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-md border bg-muted/30 px-4 py-3">
            <div className="flex items-center gap-2">
              <span className="text-2xl font-semibold tabular-nums text-foreground">{remaining}</span>
              <span className="text-sm text-muted-foreground">active code{remaining === 1 ? '' : 's'} on file</span>
            </div>
            <BoolBadge on={remaining > 0} labelOn="Available" labelOff="None" />
          </div>
        </CardContent>
        <CardFooter className="justify-end gap-2 border-t bg-muted/30 px-6 py-3">
          <ConfirmDialog
            destructive={remaining > 0}
            title={remaining > 0 ? 'Regenerate recovery codes?' : 'Generate recovery codes?'}
            description={
              remaining > 0
                ? 'Existing recovery codes will stop working. Save the new ones in a secure place.'
                : 'You will be shown 10 single-use codes. Save them somewhere safe — they will not be shown again.'
            }
            confirmLabel={remaining > 0 ? 'Regenerate' : 'Generate'}
            loading={regenerate.isPending}
            onConfirm={async () => {
              await regenerate.mutateAsync()
            }}
            trigger={
              <Button>
                <RefreshCw className="h-4 w-4" />
                {remaining > 0 ? 'Regenerate codes' : 'Generate codes'}
              </Button>
            }
          />
        </CardFooter>
      </Card>

      <Dialog open={!!codes} onOpenChange={(o) => !o && setCodes(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Your new recovery codes</DialogTitle>
            <DialogDescription>
              Save these codes now — they will not be shown again. Each works exactly once.
            </DialogDescription>
          </DialogHeader>
          {codes && <SecretReveal value={codes.join(' ')} layout="grid" />}
        </DialogContent>
      </Dialog>
    </>
  )
}
