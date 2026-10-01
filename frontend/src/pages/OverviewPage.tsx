import { useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { ArrowRight, CircleOff, FilePlus2, ShieldCheck } from 'lucide-react'
import { EmptyState } from '../components/EmptyState'
import { PageHeader } from '../components/PageHeader'
import { StateBadge } from '../components/StateBadge'
import { appConfiguration } from '../services/configuration'

type DashboardPerspective = 'CISO' | 'Auditor' | 'Admin'

const perspectiveStorageKey = 'ipsec-dashboard-perspective'

function readPerspective(): DashboardPerspective {
  try {
    const stored = localStorage.getItem(perspectiveStorageKey)
    if (stored === 'CISO' || stored === 'Auditor' || stored === 'Admin') return stored
  } catch {
    // Storage can be unavailable in hardened browser contexts; default to CISO.
  }
  return 'CISO'
}

export function OverviewPage() {
  const [perspective, setPerspective] = useState<DashboardPerspective>(readPerspective)

  useEffect(() => {
    try {
      localStorage.setItem(perspectiveStorageKey, perspective)
    } catch {
      // A view preference is optional and does not affect access or authorization.
    }
  }, [perspective])

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow={`DASHBOARD / ${perspective} PERSPECTIVE`}
        title="IPsec security assessment"
        description={perspectiveDescription[perspective]}
        actions={<>
          <label className="perspective-select"><span>Dashboard perspective</span><select value={perspective} onChange={(event) => setPerspective(event.target.value as DashboardPerspective)} aria-describedby="perspective-disclaimer"><option value="CISO">CISO</option><option value="Auditor">Auditor</option><option value="Admin">Admin</option></select></label>
          {perspective === 'Admin' && <Link className="button button--primary" to="/analysis"><FilePlus2 size={15} /> New analysis</Link>}
        </>}
      />

      <p className="perspective-disclaimer" id="perspective-disclaimer">Display perspective only. This selector does not authenticate users or change permissions.</p>

      {appConfiguration.apiConfigured ? (
        <section className="connection-banner" style={{ borderColor: 'rgba(34,197,94,0.3)', background: 'rgba(34,197,94,0.05)' }} aria-label="Backend connection state">
          <div className="connection-banner__icon" style={{ color: '#22c55e' }}><ShieldCheck size={18} aria-hidden="true" /></div>
          <div className="connection-banner__copy">
            <strong style={{ color: '#4ade80' }}>Backend contract active &amp; connected</strong>
            <p>Connected to Valence-IPsec API at {appConfiguration.apiBaseUrl}. Fleet store, live probing, and PCAP analysis operational.</p>
          </div>
          <Link className="text-link" to="/fleet">Explore fleet <ArrowRight size={14} /></Link>
        </section>
      ) : (
        <section className="connection-banner" aria-label="Backend connection state">
          <div className="connection-banner__icon"><CircleOff size={18} aria-hidden="true" /></div>
          <div className="connection-banner__copy">
            <strong>Backend contract unavailable</strong>
            <p>No API specification or service URL is configured. Dashboard values, findings, and event history cannot be loaded.</p>
          </div>
          <Link className="text-link" to="/system">Review configuration <ArrowRight size={14} /></Link>
        </section>
      )}

      {perspective === 'CISO' && <CisoDashboard />}
      {perspective === 'Auditor' && <AuditorDashboard />}
      {perspective === 'Admin' && <AdminDashboard />}

      <div className="overview-note"><ShieldCheck size={15} aria-hidden="true" /><span>Display perspectives organize information; backend authentication and authorization are not yet integrated.</span></div>
    </div>
  )
}

const perspectiveDescription: Record<DashboardPerspective, string> = {
  CISO: 'Security posture, fleet exposure, findings, and report availability. Values remain unavailable until backend integration.',
  Auditor: 'Evidence provenance, compliance controls, signed attestations, and audit history. Records are not inferred or fabricated.',
  Admin: 'Gateway inventory, probe and analysis operations, and service configuration. Operational actions require backend contracts.',
}

function Metric({ label, state, link, to }: { label: string; state: string; link: string; to: string }) {
  return <article className="metric-cell"><div className="metric-label">{label}</div><div className="metric-value metric-value--empty metric-value--text">{state}</div><div className="metric-foot"><span>Unavailable</span><Link to={to}>{link}</Link></div></article>
}

function MetricStrip({ items }: { items: Array<{ label: string; link: string; to: string }> }) {
  return <section className="overview-metrics" aria-label="Dashboard indicators">{items.map((item) => <Metric key={item.label} {...item} state="Unavailable" />)}</section>
}

function DashboardPanel({ title, eyebrow, to, link, children }: { title: string; eyebrow: string; to: string; link: string; children: ReactNode }) {
  return <section className="panel"><div className="panel-heading"><div><div className="eyebrow">{eyebrow}</div><h2>{title}</h2></div><Link className="subtle-link" to={to}>{link} <ArrowRight size={13} /></Link></div>{children}</section>
}

function CisoDashboard() {
  return <>
    <MetricStrip items={[{ label: 'Fleet posture', link: 'VPN fleet', to: '/fleet' }, { label: 'Critical findings', link: 'Risk triage', to: '/investigations' }, { label: 'Assessment coverage', link: 'Analysis', to: '/analysis' }, { label: 'Reports available', link: 'Reports', to: '/reports' }]} />
    <section className="section-block"><div className="section-heading"><div><div className="eyebrow">EXECUTIVE REVIEW</div><h2>Security posture inputs</h2></div><StateBadge>Awaiting assessment data</StateBadge></div><div className="overview-grid">
      <DashboardPanel eyebrow="FLEET RISK" title="Fleet overview" to="/fleet" link="Open fleet"><EmptyState title="Fleet posture unavailable" description="Gateway status and risk distribution are not supplied. No security conclusion can be drawn." compact /></DashboardPanel>
      <DashboardPanel eyebrow="PRIORITIZATION" title="Findings requiring attention" to="/investigations" link="Investigations"><EmptyState title="Finding data unavailable" description="Criticality and affected-asset context will appear when findings are returned by the backend." compact /></DashboardPanel>
      <DashboardPanel eyebrow="OUTPUTS" title="Assessment reports" to="/reports" link="Reports"><EmptyState title="No report metadata loaded" description="Generated assessments and signed outputs will be listed when returned by the reporting service." compact /></DashboardPanel>
      <DashboardPanel eyebrow="TREND DATA" title="Posture changes" to="/reports" link="Review reports"><EmptyState title="Trend data unavailable" description="Historical assessment data is needed before any trend can be presented." compact /></DashboardPanel>
    </div></section>
  </>
}

function AuditorDashboard() {
  return <>
    <MetricStrip items={[{ label: 'Evidence records', link: 'Evidence', to: '/evidence' }, { label: 'Control results', link: 'Compliance', to: '/compliance' }, { label: 'Signed attestations', link: 'Reports', to: '/reports' }, { label: 'Audit history', link: 'System', to: '/system' }]} />
    <section className="section-block"><div className="section-heading"><div><div className="eyebrow">ASSURANCE REVIEW</div><h2>Evidence and control traceability</h2></div><StateBadge>Awaiting backend records</StateBadge></div><div className="overview-grid">
      <DashboardPanel eyebrow="EVIDENCE LEDGER" title="Evidence records" to="/evidence" link="Evidence explorer"><EmptyState title="No evidence records loaded" description="Evidence identity, hash, signature, provenance, and verification state require backend records." compact /></DashboardPanel>
      <DashboardPanel eyebrow="RULE PACKS" title="Compliance controls" to="/compliance" link="Compliance workspace"><EmptyState title="Control results unavailable" description="Applicable rule packs and control outcomes have not been provided. No compliance status is assumed." compact /></DashboardPanel>
      <DashboardPanel eyebrow="SIGNED OUTPUT" title="Attestations" to="/reports" link="Reports and attestations"><EmptyState title="No attestation available" description="Signature verification requires a signed attestation and its associated evidence from the backend." compact /></DashboardPanel>
      <DashboardPanel eyebrow="AUDIT TRAIL" title="Recorded actions" to="/system" link="System status"><EmptyState title="Audit history unavailable" description="User actions and timestamps are shown only when an audit event source is integrated." compact /></DashboardPanel>
    </div></section>
  </>
}

function AdminDashboard() {
  return <>
    <MetricStrip items={[{ label: 'Gateway inventory', link: 'VPN fleet', to: '/fleet' }, { label: 'Probe jobs', link: 'Live probe', to: '/probe' }, { label: 'Analysis jobs', link: 'PCAP analysis', to: '/analysis' }, { label: 'Service state', link: 'System', to: '/system' }]} />
    <section className="section-block"><div className="section-heading"><div><div className="eyebrow">INFRASTRUCTURE OPERATIONS</div><h2>Fleet services and processing</h2></div><StateBadge>Backend unavailable</StateBadge></div><div className="overview-grid">
      <DashboardPanel eyebrow="ASSET INVENTORY" title="Gateway connectivity" to="/fleet" link="Open fleet"><EmptyState title="Gateway inventory unavailable" description="Gateway addresses, vendor details, tunnel state, and last probe are not loaded." compact /></DashboardPanel>
      <DashboardPanel eyebrow="ACTIVE DISCOVERY" title="Probe operations" to="/probe" link="Live probe"><EmptyState title="Probe state unavailable" description="Probe queue and run results require the documented probe API and authorization contract." compact /></DashboardPanel>
      <DashboardPanel eyebrow="TRAFFIC ANALYSIS" title="Analysis processing" to="/analysis" link="PCAP analysis"><EmptyState title="Analysis jobs unavailable" description="Ingestion and processing state will be shown only from backend job updates." compact /></DashboardPanel>
      <DashboardPanel eyebrow="SERVICE HEALTH" title="Integration readiness" to="/system" link="System configuration"><div className="service-list"><div><span>API service</span><StateBadge tone="warning">Not configured</StateBadge></div><div><span>Event stream</span><StateBadge>Disconnected</StateBadge></div><div><span>Identity provider</span><StateBadge>Not configured</StateBadge></div><div><span>Assessment telemetry</span><StateBadge>Awaiting telemetry</StateBadge></div></div></DashboardPanel>
    </div></section>
  </>
}
