import type { ComponentType, SVGProps } from 'react'
import {
  Activity,
  KeyRound,
  Lock,
  ShieldCheck,
  UserRound,
  Users,
  Boxes,
  LayoutDashboard,
} from 'lucide-react'

type IconType = ComponentType<SVGProps<SVGSVGElement>>

export interface NavItem {
  to: string
  label: string
  icon: IconType
  end?: boolean
}

export interface NavGroup {
  label: string
  items: NavItem[]
}

export const portalNav: NavGroup[] = [
  {
    label: 'Account',
    items: [
      { to: '/portal', label: 'Profile', icon: UserRound, end: true },
      { to: '/portal/password', label: 'Password', icon: Lock },
    ],
  },
  {
    label: 'Security',
    items: [
      { to: '/portal/mfa', label: 'Multi-factor', icon: ShieldCheck },
      { to: '/portal/sessions', label: 'Sessions', icon: Activity },
      { to: '/portal/consents', label: 'Authorized apps', icon: KeyRound },
    ],
  },
]

export const adminNav: NavGroup[] = [
  {
    label: 'Overview',
    items: [{ to: '/admin', label: 'Dashboard', icon: LayoutDashboard, end: true }],
  },
  {
    label: 'Tenant',
    items: [
      { to: '/admin/clients', label: 'OAuth clients', icon: Boxes },
      { to: '/admin/users', label: 'Users', icon: Users },
    ],
  },
  {
    label: 'Observability',
    items: [{ to: '/admin/audit', label: 'Audit log', icon: Activity }],
  },
]
