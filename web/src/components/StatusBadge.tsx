import type { ReactNode } from 'react'
import { CheckCircle2, ShieldAlert, ShieldCheck, ShieldOff, Circle } from 'lucide-react'

import { Badge, type BadgeProps } from '@/components/ui/badge'
import { cn } from '@/lib/utils'

export type Tone = 'success' | 'warning' | 'danger' | 'info' | 'neutral' | 'primary'

const variantByTone: Record<Tone, BadgeProps['variant']> = {
  success: 'success',
  warning: 'warning',
  danger: 'destructive',
  info: 'info',
  neutral: 'secondary',
  primary: 'default',
}

interface StatusBadgeProps {
  tone?: Tone
  children: ReactNode
  icon?: ReactNode
  className?: string
}

export function StatusBadge({ tone = 'neutral', children, icon, className }: StatusBadgeProps) {
  return (
    <Badge variant={variantByTone[tone]} className={cn('gap-1.5', className)}>
      {icon}
      {children}
    </Badge>
  )
}

export function MfaLevelBadge({ level }: { level: string }) {
  const normalized = (level || '').toLowerCase()
  if (normalized === 'mfa' || normalized === 'aal2' || normalized === 'aal3') {
    return (
      <StatusBadge tone="success" icon={<ShieldCheck className="h-3 w-3" />}>
        MFA verified
      </StatusBadge>
    )
  }
  if (normalized === 'pwd' || normalized === 'aal1') {
    return (
      <StatusBadge tone="warning" icon={<ShieldAlert className="h-3 w-3" />}>
        Password only
      </StatusBadge>
    )
  }
  if (!normalized) {
    return (
      <StatusBadge tone="neutral" icon={<Circle className="h-3 w-3" />}>
        Unknown
      </StatusBadge>
    )
  }
  return (
    <StatusBadge tone="neutral" icon={<ShieldOff className="h-3 w-3" />}>
      {level}
    </StatusBadge>
  )
}

export function BoolBadge({
  on,
  labelOn = 'Enabled',
  labelOff = 'Disabled',
}: {
  on: boolean
  labelOn?: string
  labelOff?: string
}) {
  return on ? (
    <StatusBadge tone="success" icon={<CheckCircle2 className="h-3 w-3" />}>
      {labelOn}
    </StatusBadge>
  ) : (
    <StatusBadge tone="neutral">{labelOff}</StatusBadge>
  )
}
