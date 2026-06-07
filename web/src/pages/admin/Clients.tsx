import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { Boxes, ChevronRight, Search } from 'lucide-react'

import { get } from '@/api/client'
import type { AdminClient } from '@/api/adminTypes'
import { DataTableShell } from '@/components/DataTable'
import { PageHeader } from '@/components/PageHeader'
import { EmptyState, ErrorState, LoadingState } from '@/components/StateViews'
import { StatusBadge } from '@/components/StatusBadge'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'

export function Clients() {
  const [query, setQuery] = useState('')
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['admin-clients'],
    queryFn: () => get<AdminClient[]>('/admin/api/v1/clients'),
  })

  const filtered = useMemo(() => {
    if (!data) return []
    const q = query.trim().toLowerCase()
    if (!q) return data
    return data.filter(
      (c) =>
        c.name.toLowerCase().includes(q) ||
        c.client_id.toLowerCase().includes(q) ||
        c.client_type.toLowerCase().includes(q),
    )
  }, [data, query])

  return (
    <>
      <PageHeader
        eyebrow="Tenant"
        title="OAuth clients"
        description="Applications that can request tokens from this tenant. Click a row to inspect or rotate credentials."
        actions={
          <Button disabled className="cursor-not-allowed opacity-60" title="Wired in a later milestone">
            New client
          </Button>
        }
      />

      {isLoading && <LoadingState variant="table" rows={5} />}
      {error && <ErrorState message="We couldn't load the clients list." onRetry={() => void refetch()} />}
      {data && data.length === 0 && (
        <EmptyState
          icon={Boxes}
          title="No clients registered"
          description="Once you register an OAuth client in this tenant, it will appear here."
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
                placeholder="Filter by name, client_id, or type"
                className="h-9 pl-9"
              />
            </div>
          }
        >
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Client ID</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Auth method</TableHead>
                <TableHead>Grants</TableHead>
                <TableHead className="w-12" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.map((c) => (
                <TableRow key={c.id} className="cursor-pointer">
                  <TableCell>
                    <Link to={`/admin/clients/${c.id}`} className="text-sm font-medium text-foreground hover:underline">
                      {c.name}
                    </Link>
                  </TableCell>
                  <TableCell>
                    <span className="font-mono text-xs text-muted-foreground">{c.client_id}</span>
                  </TableCell>
                  <TableCell>
                    <StatusBadge tone={c.client_type === 'confidential' ? 'info' : 'neutral'}>
                      {c.client_type}
                    </StatusBadge>
                  </TableCell>
                  <TableCell>
                    <span className="font-mono text-xs">{c.token_endpoint_auth_method}</span>
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {c.grant_types.map((g) => (
                        <Badge key={g} variant="outline" className="font-mono text-[10px]">
                          {g}
                        </Badge>
                      ))}
                    </div>
                  </TableCell>
                  <TableCell className="text-right">
                    <Button asChild variant="ghost" size="icon">
                      <Link to={`/admin/clients/${c.id}`} aria-label={`Edit ${c.name}`}>
                        <ChevronRight />
                      </Link>
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
              {filtered.length === 0 && (
                <TableRow>
                  <TableCell colSpan={6} className="py-12 text-center text-sm text-muted-foreground">
                    No clients match "{query}".
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </DataTableShell>
      )}
    </>
  )
}
