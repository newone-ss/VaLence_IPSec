import { AlertCircle, CircleOff, LoaderCircle, LockKeyhole } from 'lucide-react'
import type { ReactNode } from 'react'

interface RequestStateProps {
  title: string
  description: string
  action?: ReactNode
}

export function LoadingState({ title, description }: RequestStateProps) {
  return <RequestState icon={<LoaderCircle className="request-state__spinner" size={17} aria-hidden="true" />} title={title} description={description} />
}

export function ErrorState({ title, description, action }: RequestStateProps) {
  return <RequestState icon={<AlertCircle size={17} aria-hidden="true" />} title={title} description={description} action={action} tone="error" />
}

export function UnauthorizedState({ title = 'Access not authorized', description }: Partial<RequestStateProps>) {
  return <RequestState icon={<LockKeyhole size={17} aria-hidden="true" />} title={title} description={description ?? 'The identity provider and authorization contract have not been configured.'} />
}

export function OfflineState({ title = 'Service unavailable', description, action }: Partial<RequestStateProps>) {
  return <RequestState icon={<CircleOff size={17} aria-hidden="true" />} title={title} description={description ?? 'The backend is not connected. Operational data and actions are unavailable.'} action={action} />
}

function RequestState({
  icon,
  title,
  description,
  action,
  tone = 'neutral',
}: RequestStateProps & { icon: ReactNode; tone?: 'neutral' | 'error' }) {
  return (
    <section className={`request-state request-state--${tone}`} role={tone === 'error' ? 'alert' : 'status'}>
      {icon}
      <div><strong>{title}</strong><p>{description}</p>{action && <div className="request-state__action">{action}</div>}</div>
    </section>
  )
}
