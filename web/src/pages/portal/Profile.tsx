import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'
import { CheckCircle2, MailWarning, Trash2 } from 'lucide-react'
import { toast } from 'sonner'

import { del, get, postJSON } from '@/api/client'
import type { UserProfile } from '@/api/types'
import { ConfirmDialog } from '@/components/ConfirmDialog'
import { PageHeader } from '@/components/PageHeader'
import { ErrorState, LoadingState } from '@/components/StateViews'
import { StatusBadge } from '@/components/StatusBadge'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'

export function Profile() {
  const qc = useQueryClient()
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['me'],
    queryFn: () => get<UserProfile>('/portal/api/v1/me'),
  })
  const [draft, setDraft] = useState<Partial<UserProfile>>({})
  const update = useMutation({
    mutationFn: (patch: Partial<UserProfile>) => postJSON<UserProfile>('/portal/api/v1/me', patch),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['me'] })
      setDraft({})
      toast.success('Profile saved')
    },
    onError: (e: Error) => toast.error(e.message),
  })
  const deleteAccount = useMutation({
    mutationFn: () => del('/portal/api/v1/me'),
    onSuccess: () => window.location.assign('/portal'),
    onError: (e: Error) => toast.error(e.message),
  })

  if (isLoading) {
    return (
      <>
        <PageHeader eyebrow="Account" title="Profile" />
        <LoadingState variant="form" />
      </>
    )
  }
  if (error || !data) {
    return (
      <>
        <PageHeader eyebrow="Account" title="Profile" />
        <ErrorState message="We couldn't load your profile." onRetry={() => void refetch()} />
      </>
    )
  }

  function onSave(e: FormEvent) {
    e.preventDefault()
    update.mutate({
      display_name: draft.display_name ?? data!.display_name,
      locale: draft.locale ?? data!.locale,
      zoneinfo: draft.zoneinfo ?? data!.zoneinfo,
      picture_url: draft.picture_url ?? data!.picture_url,
    })
  }

  return (
    <>
      <PageHeader
        eyebrow="Account"
        title="Profile"
        description={
          <div className="flex items-center gap-2">
            <span className="font-mono text-foreground">{data.email}</span>
            {data.email_verified ? (
              <StatusBadge tone="success" icon={<CheckCircle2 className="h-3 w-3" />}>
                Verified
              </StatusBadge>
            ) : (
              <StatusBadge tone="warning" icon={<MailWarning className="h-3 w-3" />}>
                Unverified
              </StatusBadge>
            )}
          </div>
        }
      />

      <div className="space-y-6">
        <Card>
          <CardHeader>
            <CardTitle>Account details</CardTitle>
            <CardDescription>
              How keyforge addresses you, and what timezone and locale to use across the portal.
            </CardDescription>
          </CardHeader>
          <form onSubmit={onSave}>
            <CardContent className="grid grid-cols-1 gap-4 md:grid-cols-2">
              <div className="space-y-1.5 md:col-span-2">
                <Label htmlFor="display_name">Display name</Label>
                <Input
                  id="display_name"
                  defaultValue={data.display_name}
                  onChange={(e) => setDraft({ ...draft, display_name: e.target.value })}
                  placeholder="Your name"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="locale">Locale</Label>
                <Input
                  id="locale"
                  defaultValue={data.locale}
                  onChange={(e) => setDraft({ ...draft, locale: e.target.value })}
                  placeholder="en"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="zoneinfo">Time zone</Label>
                <Input
                  id="zoneinfo"
                  defaultValue={data.zoneinfo}
                  onChange={(e) => setDraft({ ...draft, zoneinfo: e.target.value })}
                  placeholder="UTC"
                />
              </div>
              <div className="space-y-1.5 md:col-span-2">
                <Label htmlFor="picture_url">Picture URL</Label>
                <Input
                  id="picture_url"
                  defaultValue={data.picture_url}
                  onChange={(e) => setDraft({ ...draft, picture_url: e.target.value })}
                  placeholder="https://…"
                />
              </div>
            </CardContent>
            <CardFooter className="justify-end gap-2 border-t bg-muted/30 px-6 py-3">
              <Button type="submit" disabled={update.isPending}>
                {update.isPending ? 'Saving…' : 'Save changes'}
              </Button>
            </CardFooter>
          </form>
        </Card>

        <Card className="border-destructive/30">
          <CardHeader>
            <CardTitle className="text-destructive">Danger zone</CardTitle>
            <CardDescription>
              Schedules your account for deletion. Active sessions are revoked immediately;
              the record is permanently removed after the retention window.
            </CardDescription>
          </CardHeader>
          <CardFooter className="border-t bg-destructive/[0.03] px-6 py-3">
            <ConfirmDialog
              destructive
              title="Delete this account?"
              description="This cannot be undone. Sessions, consents, MFA methods, and the user record will be removed after the retention window."
              confirmLabel="Delete account"
              loading={deleteAccount.isPending}
              onConfirm={() => deleteAccount.mutateAsync()}
              trigger={
                <Button variant="destructive">
                  <Trash2 className="h-4 w-4" />
                  Delete account
                </Button>
              }
            />
          </CardFooter>
        </Card>
      </div>
    </>
  )
}
