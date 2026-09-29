import type { ReactNode } from 'react'

export type StateTone = 'neutral' | 'info' | 'success' | 'warning' | 'critical'

export function StateBadge({ children, tone = 'neutral' }: { children: ReactNode; tone?: StateTone }) {
  return (
    <span className={`state-badge state-badge--${tone}`}>
      <span className="state-badge__mark" aria-hidden="true" />
      {children}
    </span>
  )
}
