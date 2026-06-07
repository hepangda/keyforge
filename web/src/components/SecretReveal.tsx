import { useState } from 'react'
import { Check, Copy } from 'lucide-react'
import { toast } from 'sonner'

import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'

interface SecretRevealProps {
  value: string
  className?: string
  layout?: 'inline' | 'grid'
}

export function SecretReveal({ value, className, layout = 'inline' }: SecretRevealProps) {
  const [copied, setCopied] = useState(false)

  async function copy() {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      toast.success('Copied to clipboard')
      setTimeout(() => setCopied(false), 1500)
    } catch {
      toast.error('Clipboard unavailable')
    }
  }

  if (layout === 'grid') {
    const items = value.split(/\s+/).filter(Boolean)
    return (
      <div className={className}>
        <ul className="grid grid-cols-2 gap-2 sm:grid-cols-3">
          {items.map((code, i) => (
            <li
              key={`${code}-${i}`}
              className="rounded-md border bg-muted/40 px-3 py-2 font-mono text-sm text-foreground"
            >
              {code}
            </li>
          ))}
        </ul>
        <div className="mt-3 flex justify-end">
          <Button type="button" size="sm" variant="outline" onClick={copy}>
            {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
            {copied ? 'Copied' : 'Copy all'}
          </Button>
        </div>
      </div>
    )
  }

  return (
    <div
      className={cn(
        'flex items-center justify-between gap-3 rounded-md border bg-muted/40 px-3 py-2 font-mono text-sm',
        className,
      )}
    >
      <span className="truncate">{value}</span>
      <Button type="button" size="sm" variant="ghost" onClick={copy}>
        {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
        <span className="sr-only">Copy</span>
      </Button>
    </div>
  )
}
