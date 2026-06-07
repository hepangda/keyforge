import { useMutation } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'
import { AlertCircle, Lock } from 'lucide-react'
import { toast } from 'sonner'

import { postJSON } from '@/api/client'
import { PageHeader } from '@/components/PageHeader'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'

export function Password() {
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [err, setErr] = useState<string | null>(null)

  const change = useMutation({
    mutationFn: () =>
      postJSON<void>('/portal/api/v1/password', {
        current_password: current,
        new_password: next,
      }),
    onSuccess: () => {
      setCurrent('')
      setNext('')
      setConfirm('')
      setErr(null)
      toast.success('Password updated')
    },
    onError: (e: Error) => {
      setErr(e.message)
    },
  })

  function onSubmit(e: FormEvent) {
    e.preventDefault()
    setErr(null)
    if (next.length < 8) {
      setErr('New password must be at least 8 characters.')
      return
    }
    if (next !== confirm) {
      setErr('New passwords do not match.')
      return
    }
    change.mutate()
  }

  return (
    <>
      <PageHeader
        eyebrow="Account"
        title="Password"
        description="Update the password you use to sign in. We recommend at least 12 random characters or a passphrase."
      />

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-[1fr_280px]">
        <Card>
          <CardHeader>
            <CardTitle>Change password</CardTitle>
            <CardDescription>
              You'll be asked for your current password to confirm.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={onSubmit} className="space-y-4">
              {err && (
                <Alert variant="destructive">
                  <AlertCircle />
                  <AlertDescription>{err}</AlertDescription>
                </Alert>
              )}
              <div className="space-y-1.5">
                <Label htmlFor="pw-current">Current password</Label>
                <Input
                  id="pw-current"
                  type="password"
                  autoComplete="current-password"
                  value={current}
                  onChange={(e) => setCurrent(e.target.value)}
                  required
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="pw-next">New password</Label>
                <Input
                  id="pw-next"
                  type="password"
                  autoComplete="new-password"
                  value={next}
                  onChange={(e) => setNext(e.target.value)}
                  required
                  minLength={8}
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="pw-confirm">Confirm new password</Label>
                <Input
                  id="pw-confirm"
                  type="password"
                  autoComplete="new-password"
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                  required
                  minLength={8}
                />
              </div>
              <div className="flex justify-end pt-2">
                <Button type="submit" disabled={change.isPending}>
                  {change.isPending ? 'Updating…' : 'Update password'}
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>

        <Card className="self-start bg-surface">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-sm">
              <Lock className="h-4 w-4 text-primary" />
              Password tips
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 text-sm text-muted-foreground">
            <p>
              keyforge stores passwords with Argon2id hashing. Even keyforge operators
              can't see your password — only verify it.
            </p>
            <p>
              For the strongest accounts, pair your password with a passkey or
              authenticator app from the Multi-factor page.
            </p>
          </CardContent>
        </Card>
      </div>
    </>
  )
}
