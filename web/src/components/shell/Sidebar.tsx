import { NavLink } from 'react-router-dom'

import { ScrollArea } from '@/components/ui/scroll-area'
import { cn } from '@/lib/utils'
import { BrandWordmark } from './BrandMark'
import { UserMenu } from './UserMenu'
import { adminNav, portalNav, type NavGroup } from './navConfig'

export function Sidebar({ section }: { section: 'portal' | 'admin' }) {
  const groups: NavGroup[] = section === 'portal' ? portalNav : adminNav
  return (
    <aside className="flex h-screen flex-col bg-sidebar text-sidebar-foreground">
      <div className="border-b border-sidebar-border/70 px-5 py-5">
        <BrandWordmark />
      </div>
      <div className="flex items-center justify-between border-b border-sidebar-border/70 px-5 py-3">
        <span className="text-[10px] font-semibold uppercase tracking-[0.18em] text-sidebar-muted">
          {section === 'portal' ? 'My account' : 'Administration'}
        </span>
        <span className="rounded-full bg-sidebar-accent px-2 py-0.5 text-[10px] font-medium uppercase tracking-wider text-sidebar-foreground/80">
          v1
        </span>
      </div>
      <ScrollArea className="flex-1 px-3 py-4">
        <nav className="flex flex-col gap-6">
          {groups.map((group) => (
            <div key={group.label} className="flex flex-col gap-1">
              <div className="px-3 pb-1 text-[10px] font-semibold uppercase tracking-[0.16em] text-sidebar-muted">
                {group.label}
              </div>
              {group.items.map((item) => {
                const Icon = item.icon
                return (
                  <NavLink
                    key={item.to}
                    to={item.to}
                    end={item.end}
                    className={({ isActive }) =>
                      cn(
                        'group flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors',
                        isActive
                          ? 'bg-sidebar-accent text-sidebar-foreground shadow-[inset_2px_0_0_hsl(var(--accent))]'
                          : 'text-sidebar-foreground/75 hover:bg-sidebar-accent/60 hover:text-sidebar-foreground',
                      )
                    }
                  >
                    <Icon className="h-4 w-4 text-sidebar-muted group-hover:text-sidebar-foreground group-aria-[current=page]:text-accent" />
                    <span>{item.label}</span>
                  </NavLink>
                )
              })}
            </div>
          ))}
        </nav>
      </ScrollArea>
      <div className="border-t border-sidebar-border/70 p-3">
        <UserMenu section={section} />
      </div>
    </aside>
  )
}
