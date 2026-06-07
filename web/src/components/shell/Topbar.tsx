import type { ReactNode } from 'react'
import { Link, useLocation } from 'react-router-dom'

import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from '@/components/ui/breadcrumb'

interface TopbarProps {
  section: 'portal' | 'admin'
  children?: ReactNode
}

function labelFor(segment: string): string {
  return segment
    .split('-')
    .map((s) => s.charAt(0).toUpperCase() + s.slice(1))
    .join(' ')
}

export function Topbar({ section, children }: TopbarProps) {
  const loc = useLocation()
  const parts = loc.pathname.split('/').filter(Boolean)
  const sectionLabel = section === 'portal' ? 'Portal' : 'Admin'
  const tail = parts.slice(1)
  return (
    <header className="sticky top-0 z-30 flex h-14 items-center justify-between border-b bg-background/95 px-6 backdrop-blur supports-[backdrop-filter]:bg-background/75">
      <Breadcrumb>
        <BreadcrumbList>
          <BreadcrumbItem>
            <BreadcrumbLink asChild>
              <Link to={`/${section}`}>{sectionLabel}</Link>
            </BreadcrumbLink>
          </BreadcrumbItem>
          {tail.map((seg, i) => {
            const isLast = i === tail.length - 1
            const href = '/' + parts.slice(0, i + 2).join('/')
            return (
              <span key={href} className="contents">
                <BreadcrumbSeparator />
                <BreadcrumbItem>
                  {isLast ? (
                    <BreadcrumbPage>{labelFor(seg)}</BreadcrumbPage>
                  ) : (
                    <BreadcrumbLink asChild>
                      <Link to={href}>{labelFor(seg)}</Link>
                    </BreadcrumbLink>
                  )}
                </BreadcrumbItem>
              </span>
            )
          })}
        </BreadcrumbList>
      </Breadcrumb>
      <div className="flex items-center gap-2">{children}</div>
    </header>
  )
}
