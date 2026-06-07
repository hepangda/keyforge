import { Link } from 'react-router-dom'
import { Activity, Boxes, Users } from 'lucide-react'

import { PageHeader } from '@/components/PageHeader'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'

interface TileProps {
  title: string
  description: string
  to: string
  icon: typeof Boxes
}

function Tile({ title, description, to, icon: Icon }: TileProps) {
  return (
    <Link
      to={to}
      className="group flex flex-col rounded-lg border bg-card p-5 shadow-sm transition-colors hover:border-primary/40 hover:bg-primary/[0.02]"
    >
      <div className="flex items-center gap-3">
        <div className="flex h-9 w-9 items-center justify-center rounded-md bg-primary/10 text-primary">
          <Icon className="h-4 w-4" />
        </div>
        <div className="text-sm font-semibold text-foreground">{title}</div>
      </div>
      <div className="mt-3 text-sm text-muted-foreground">{description}</div>
      <div className="mt-4 text-xs font-medium uppercase tracking-wider text-primary opacity-0 transition-opacity group-hover:opacity-100">
        Open →
      </div>
    </Link>
  )
}

export function AdminOverview() {
  return (
    <>
      <PageHeader
        eyebrow="Tenant administration"
        title="Welcome back"
        description="Manage OAuth clients, users, and audit activity for your tenant. Pick a section to get started."
      />
      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <Tile
          title="OAuth clients"
          description="Register, configure, and rotate credentials for applications integrating with keyforge."
          to="/admin/clients"
          icon={Boxes}
        />
        <Tile
          title="Users"
          description="Review accounts, manage roles, and inspect verification status."
          to="/admin/users"
          icon={Users}
        />
        <Tile
          title="Audit log"
          description="Trace authentication, consent, and administrative events across the tenant."
          to="/admin/audit"
          icon={Activity}
        />
      </div>
      <Card className="mt-8">
        <CardHeader>
          <CardTitle>What's next</CardTitle>
          <CardDescription>
            Dashboards for sign-in volume, MFA adoption, and active sessions land in upcoming milestones.
          </CardDescription>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground">
          Until then, the audit log is the source of truth for tenant activity.
        </CardContent>
      </Card>
    </>
  )
}
