import type { ReactNode } from 'react'
import { ArrowRight, DatabaseX } from 'lucide-react'

interface EmptyStateProps {
  title: string
  description: string
  action?: ReactNode
  compact?: boolean
}

export function EmptyState({ title, description, action, compact = false }: EmptyStateProps) {
  return (
    <div className={`empty-state${compact ? ' empty-state--compact' : ''}`}>
      <DatabaseX aria-hidden="true" size={18} strokeWidth={1.7} />
      <div className="empty-state__copy">
        <h3>{title}</h3>
        <p>{description}</p>
      </div>
      {action && <div className="empty-state__action">{action}<ArrowRight size={14} aria-hidden="true" /></div>}
    </div>
  )
}
