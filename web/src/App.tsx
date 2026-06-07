import { useEffect, useRef, useState, type ReactNode } from 'react'
import { BrowserRouter, Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ShieldAlert } from 'lucide-react'

import { bearer, beginLogin, completeLogin } from '@/auth/oidc'
import { AppShell } from '@/components/shell/AppShell'
import { BrandWordmark } from '@/components/shell/BrandMark'
import { Profile } from '@/pages/portal/Profile'
import { Sessions } from '@/pages/portal/Sessions'
import { Consents } from '@/pages/portal/Consents'
import { Mfa } from '@/pages/portal/Mfa'
import { Password } from '@/pages/portal/Password'
import { Clients } from '@/pages/admin/Clients'
import { ClientEdit } from '@/pages/admin/ClientEdit'
import { Users } from '@/pages/admin/Users'
import { Audit } from '@/pages/admin/Audit'
import { AdminOverview } from '@/pages/admin/Overview'

const qc = new QueryClient({
  defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } },
})

export function App() {
  return (
    <QueryClientProvider client={qc}>
      <BrowserRouter>
        <Routes>
          <Route path="/portal/callback" element={<Callback />} />
          <Route path="/portal/*" element={<Protected><PortalShell /></Protected>} />
          <Route path="/admin/*" element={<Protected><AdminShell /></Protected>} />
          <Route path="/" element={<Navigate to="/portal" replace />} />
          <Route path="*" element={<NotFound />} />
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  )
}

function Protected({ children }: { children: ReactNode }) {
  const loc = useLocation()
  const has = !!bearer()
  const fired = useRef(false)
  useEffect(() => {
    if (!has && !fired.current) {
      fired.current = true
      void beginLogin(loc.pathname + loc.search)
    }
  }, [has, loc.pathname, loc.search])
  if (!has) return <SplashScreen title="Redirecting to sign-in" subtitle="Hold tight while we hand off to the authorization server." />
  return <>{children}</>
}

function Callback() {
  const nav = useNavigate()
  const [err, setErr] = useState<string | null>(null)
  const fired = useRef(false)
  useEffect(() => {
    if (bearer() || fired.current) {
      nav('/portal', { replace: true })
      return
    }
    fired.current = true
    completeLogin(window.location.href).then(
      (returnTo) => nav(returnTo || '/portal', { replace: true }),
      (e: Error) => setErr(e.message),
    )
  }, [nav])
  if (err) return <SplashScreen title="Sign-in failed" subtitle={err} variant="error" />
  return <SplashScreen title="Finishing sign-in" subtitle="Exchanging the authorization code for an access token." />
}

function PortalShell() {
  return (
    <AppShell section="portal">
      <Routes>
        <Route index element={<Profile />} />
        <Route path="sessions" element={<Sessions />} />
        <Route path="consents" element={<Consents />} />
        <Route path="mfa" element={<Mfa />} />
        <Route path="password" element={<Password />} />
      </Routes>
    </AppShell>
  )
}

function AdminShell() {
  return (
    <AppShell section="admin">
      <Routes>
        <Route index element={<AdminOverview />} />
        <Route path="clients" element={<Clients />} />
        <Route path="clients/:id" element={<ClientEdit />} />
        <Route path="users" element={<Users />} />
        <Route path="audit" element={<Audit />} />
      </Routes>
    </AppShell>
  )
}

function NotFound() {
  return (
    <SplashScreen
      title="404"
      subtitle="The page you were looking for isn't here."
      variant="error"
    />
  )
}

interface SplashScreenProps {
  title: string
  subtitle?: ReactNode
  variant?: 'default' | 'error'
}

function SplashScreen({ title, subtitle, variant = 'default' }: SplashScreenProps) {
  return (
    <div className="grid min-h-screen place-items-center bg-surface px-6">
      <div className="w-full max-w-md rounded-xl border bg-card p-8 text-center shadow-sm">
        <div className="mb-5 flex justify-center">
          {variant === 'error' ? (
            <div className="flex h-11 w-11 items-center justify-center rounded-full bg-destructive/10 text-destructive">
              <ShieldAlert className="h-5 w-5" />
            </div>
          ) : (
            <BrandWordmark className="text-foreground [&_*]:!text-foreground" />
          )}
        </div>
        <h1 className="text-lg font-semibold text-foreground">{title}</h1>
        {subtitle && <p className="mt-2 text-sm text-muted-foreground">{subtitle}</p>}
      </div>
    </div>
  )
}