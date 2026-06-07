import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Search, Settings2, UserCog, UsersRound } from 'lucide-react'
import { toast } from 'sonner'

import { del, get, postJSON } from '@/api/client'
import type { AdminRole, AdminUser } from '@/api/adminTypes'
import { ConfirmDialog } from '@/components/ConfirmDialog'
import { DataTableShell } from '@/components/DataTable'
import { PageHeader } from '@/components/PageHeader'
import { EmptyState, ErrorState, LoadingState } from '@/components/StateViews'
import { BoolBadge } from '@/components/StatusBadge'
import { Avatar, AvatarFallback } from '@/components/ui/avatar'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Separator } from '@/components/ui/separator'
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from '@/components/ui/sheet'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'

function initials(email: string, displayName: string): string {
  const source = displayName?.trim() || email
  const parts = source.split(/[\s@.]+/).filter(Boolean)
  if (!parts.length) return '?'
  if (parts.length === 1) return parts[0]!.slice(0, 2).toUpperCase()
  return (parts[0]![0]! + parts[1]![0]!).toUpperCase()
}

export function Users() {
  const [query, setQuery] = useState('')
  const [selected, setSelected] = useState<AdminUser | null>(null)
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['admin-users'],
    queryFn: () => get<AdminUser[]>('/admin/api/v1/users'),
  })

  const filtered = useMemo(() => {
    if (!data) return []
    const q = query.trim().toLowerCase()
    if (!q) return data
    return data.filter(
      (u) =>
        u.email.toLowerCase().includes(q) ||
        (u.display_name || '').toLowerCase().includes(q),
    )
  }, [data, query])

  return (
    <>
      <PageHeader
        eyebrow="Tenant"
        title="Users"
        description="Every account belonging to this tenant. Open a user to manage their roles."
      />

      {isLoading && <LoadingState variant="table" rows={5} />}
      {error && <ErrorState message="We couldn't load the users list." onRetry={() => void refetch()} />}
      {data && data.length === 0 && (
        <EmptyState
          icon={UsersRound}
          title="No users yet"
          description="Once accounts are provisioned, they'll show up here."
        />
      )}

      {data && data.length > 0 && (
        <DataTableShell
          toolbar={
            <div className="relative w-full max-w-sm">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
              <Input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Filter by email or name"
                className="h-9 pl-9"
              />
            </div>
          }
        >
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>User</TableHead>
                <TableHead>Email</TableHead>
                <TableHead>Verified</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="w-32" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.map((u) => (
                <TableRow key={u.id} data-state={selected?.id === u.id ? 'selected' : undefined}>
                  <TableCell>
                    <div className="flex items-center gap-3">
                      <Avatar className="h-8 w-8">
                        <AvatarFallback>{initials(u.email, u.display_name)}</AvatarFallback>
                      </Avatar>
                      <div className="leading-tight">
                        <div className="text-sm font-medium text-foreground">
                          {u.display_name || u.email.split('@')[0]}
                        </div>
                        <div className="font-mono text-[11px] text-muted-foreground">{u.id}</div>
                      </div>
                    </div>
                  </TableCell>
                  <TableCell className="font-mono text-xs text-muted-foreground">{u.email}</TableCell>
                  <TableCell>
                    <BoolBadge on={u.email_verified} labelOn="Verified" labelOff="Unverified" />
                  </TableCell>
                  <TableCell>
                    <BoolBadge on={u.enabled} labelOn="Active" labelOff="Disabled" />
                  </TableCell>
                  <TableCell className="text-right">
                    <Button variant="ghost" size="sm" onClick={() => setSelected(u)}>
                      <Settings2 className="h-4 w-4" />
                      Manage roles
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
              {filtered.length === 0 && (
                <TableRow>
                  <TableCell colSpan={5} className="py-12 text-center text-sm text-muted-foreground">
                    No users match "{query}".
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </DataTableShell>
      )}

      <Sheet open={!!selected} onOpenChange={(o) => !o && setSelected(null)}>
        <SheetContent className="flex flex-col gap-6 sm:max-w-md">
          {selected && <UserRolesPanel user={selected} />}
        </SheetContent>
      </Sheet>
    </>
  )
}

function UserRolesPanel({ user }: { user: AdminUser }) {
  const qc = useQueryClient()
  const userRoles = useQuery({
    queryKey: ['admin-user-roles', user.id],
    queryFn: () => get<AdminRole[]>(`/admin/api/v1/users/${user.id}/roles`),
  })
  const allRoles = useQuery({
    queryKey: ['admin-roles'],
    queryFn: () => get<AdminRole[]>('/admin/api/v1/roles'),
  })
  const grant = useMutation({
    mutationFn: (name: string) =>
      postJSON<void>(`/admin/api/v1/users/${user.id}/roles`, { role_name: name }),
    onSuccess: (_, name) => {
      qc.invalidateQueries({ queryKey: ['admin-user-roles', user.id] })
      toast.success(`Granted ${name}`)
    },
    onError: (e: Error) => toast.error(e.message),
  })
  const revoke = useMutation({
    mutationFn: (name: string) => del(`/admin/api/v1/users/${user.id}/roles/${name}`),
    onSuccess: (_, name) => {
      qc.invalidateQueries({ queryKey: ['admin-user-roles', user.id] })
      toast.success(`Revoked ${name}`)
    },
    onError: (e: Error) => toast.error(e.message),
  })

  const grantedNames = new Set(userRoles.data?.map((r) => r.name) ?? [])
  const grantable = (allRoles.data ?? []).filter((r) => !grantedNames.has(r.name))

  return (
    <>
      <SheetHeader>
        <div className="flex items-center gap-3">
          <Avatar className="h-10 w-10">
            <AvatarFallback>{initials(user.email, user.display_name)}</AvatarFallback>
          </Avatar>
          <div className="min-w-0 leading-tight">
            <SheetTitle className="truncate">{user.display_name || user.email}</SheetTitle>
            <SheetDescription className="truncate font-mono text-xs">{user.email}</SheetDescription>
          </div>
        </div>
      </SheetHeader>

      <Separator />

      <section className="flex-1 space-y-6 overflow-y-auto">
        <div>
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold">Assigned roles</h3>
            {userRoles.data && <Badge variant="secondary">{userRoles.data.length}</Badge>}
          </div>
          {userRoles.isLoading && <LoadingState variant="table" rows={2} className="mt-3" />}
          {userRoles.data && userRoles.data.length === 0 && (
            <p className="mt-3 rounded-md border border-dashed bg-muted/30 px-3 py-4 text-center text-sm text-muted-foreground">
              No roles assigned yet.
            </p>
          )}
          {userRoles.data && userRoles.data.length > 0 && (
            <ul className="mt-3 space-y-2">
              {userRoles.data.map((r) => (
                <li
                  key={r.name}
                  className="flex items-start justify-between gap-3 rounded-md border bg-card px-3 py-2"
                >
                  <div className="min-w-0">
                    <div className="text-sm font-medium text-foreground">{r.name}</div>
                    {r.description && (
                      <div className="text-xs text-muted-foreground">{r.description}</div>
                    )}
                  </div>
                  <ConfirmDialog
                    destructive
                    title={`Revoke ${r.name}?`}
                    description="The user loses every permission this role grants. They keep any other roles."
                    confirmLabel="Revoke"
                    loading={revoke.isPending}
                    onConfirm={() => revoke.mutateAsync(r.name)}
                    trigger={
                      <Button
                        variant="ghost"
                        size="sm"
                        className="text-destructive hover:bg-destructive/10 hover:text-destructive"
                      >
                        Revoke
                      </Button>
                    }
                  />
                </li>
              ))}
            </ul>
          )}
        </div>

        <Separator />

        <div>
          <div className="flex items-center gap-2">
            <UserCog className="h-4 w-4 text-muted-foreground" />
            <h3 className="text-sm font-semibold">Grant a role</h3>
          </div>
          {allRoles.isLoading && <LoadingState variant="table" rows={2} className="mt-3" />}
          {grantable.length === 0 && allRoles.data && (
            <p className="mt-3 text-sm text-muted-foreground">All roles are already granted.</p>
          )}
          {grantable.length > 0 && (
            <div className="mt-3 flex flex-wrap gap-2">
              {grantable.map((r) => (
                <Button
                  key={r.name}
                  variant="outline"
                  size="sm"
                  disabled={grant.isPending}
                  onClick={() => grant.mutate(r.name)}
                  title={r.description}
                >
                  + {r.name}
                </Button>
              ))}
            </div>
          )}
        </div>
      </section>
    </>
  )
}
