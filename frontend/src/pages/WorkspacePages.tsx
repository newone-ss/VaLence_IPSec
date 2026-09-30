import { useState, type ChangeEvent } from 'react'
import { Link } from 'react-router-dom'
import {
  ArrowRight,
  ChevronDown,
  CircleHelp,
  Clipboard,
  FileSearch,
  Filter,
  LockKeyhole,
  Radio,
  RefreshCw,
  Upload,
} from 'lucide-react'
import { EmptyState } from '../components/EmptyState'
import { PageHeader } from '../components/PageHeader'
import { StateBadge } from '../components/StateBadge'
import { appConfiguration } from '../services/configuration'

function IntegrationNotice({ children = 'Operational data is unavailable because the backend API specification has not been supplied.' }: { children?: string }) {
  return <div className="integration-notice"><CircleHelp size={15} aria-hidden="true" /><span>{children}</span></div>
}

export function FleetPage() {
  return (
    <div className="page-stack">
      <PageHeader eyebrow="OPERATIONS / ASSET INVENTORY" title="VPN fleet" description="Gateway inventory, tunnel state, probe history, and latest assessment results." actions={<button className="button" type="button" disabled title="Gateway provisioning requires a backend contract"><RefreshCw size={14} /> Refresh</button>} />
      <div className="toolbar-row">
        <label className="field-with-icon"><span className="sr-only">Search gateways</span><FileSearch size={15} aria-hidden="true" /><input type="search" placeholder="Search gateway, address, or vendor" disabled /></label>
        <label className="select-field"><Filter size={14} aria-hidden="true" /><span className="sr-only">Filter by status</span><select defaultValue="all" disabled><option value="all">All statuses</option></select><ChevronDown size={13} aria-hidden="true" /></label>
        <label className="select-field"><span className="sr-only">Filter by severity</span><select defaultValue="all" disabled><option value="all">All severities</option></select><ChevronDown size={13} aria-hidden="true" /></label>
        <span className="toolbar-meta">No fleet data</span>
      </div>
      <section className="table-panel" aria-label="VPN gateway inventory">
        <div className="data-table-wrap"><table className="data-table"><thead><tr><th>Gateway</th><th>Address</th><th>Vendor</th><th>IKE / IPsec</th><th>Active tunnels</th><th>Risk</th><th>Last probe</th><th>Last assessment</th></tr></thead><tbody><tr><td colSpan={8} className="table-empty"><EmptyState title="Gateway inventory unavailable" description="No backend connection is configured. Gateway presence and status are unknown; connect the fleet service to load inventory." /></td></tr></tbody></table></div>
      </section>
      <IntegrationNotice />
    </div>
  )
}

export function ProbePage() {
  const [target, setTarget] = useState('')
  const [port, setPort] = useState('500')
  const [probeMode, setProbeMode] = useState('ike')
  return (
    <div className="page-stack">
      <PageHeader eyebrow="OPERATIONS / ACTIVE DISCOVERY" title="Live probe" description="Configure an authorized IKE/UDP probe and inspect the protocol response. No probe runs until a backend contract is integrated." actions={<StateBadge>Not running</StateBadge>} />
      <div className="split-workspace">
        <section className="panel form-panel">
          <div className="panel-heading"><div><div className="eyebrow">PROBE CONFIGURATION</div><h2>Target and parameters</h2></div><Radio size={17} className="panel-heading__icon" aria-hidden="true" /></div>
          <label className="form-field"><span>Target address or hostname</span><input value={target} onChange={(event) => setTarget(event.target.value)} placeholder="IPv4, IPv6, or hostname" autoComplete="off" /></label>
          <div className="form-grid-two">
            <label className="form-field"><span>UDP destination port</span><input inputMode="numeric" value={port} onChange={(event) => setPort(event.target.value)} /></label>
            <label className="form-field"><span>Probe profile</span><select value={probeMode} onChange={(event) => setProbeMode(event.target.value)}><option value="ike">IKE negotiation discovery</option><option value="udp">UDP reachability only</option></select></label>
          </div>
          <label className="checkbox-row"><input type="checkbox" disabled /><span>Use backend-defined safe probing limits</span><small>Unavailable</small></label>
          <div className="form-actions"><button className="button button--primary" type="button" disabled title="Probe execution is unavailable until the backend contract is integrated">Run probe</button><span>Execution unavailable</span></div>
          <IntegrationNotice>Probe submission and authorization checks require the backend API contract.</IntegrationNotice>
        </section>
        <section className="panel result-panel">
          <div className="panel-heading"><div><div className="eyebrow">PROBE RESULT</div><h2>Response details</h2></div><StateBadge>Awaiting request</StateBadge></div>
          <EmptyState title="No probe results available" description="Negotiation outcome, discovered transforms, peer behavior, and failures will appear after a backend-run probe completes." compact />
          <div className="result-field-list"><div><span>Run state</span><span>—</span></div><div><span>Target identity</span><span>—</span></div><div><span>Discovered IKE version</span><span>—</span></div><div><span>Response evidence</span><span>—</span></div></div>
        </section>
      </div>
      <section className="panel"><div className="panel-heading"><div><div className="eyebrow">HISTORY</div><h2>Previous probe runs</h2></div></div><EmptyState title="No probe history available" description="Probe records are not loaded. No synthetic activity is shown." compact /></section>
    </div>
  )
}

const analysisStages = [
  ['Ingestion', 'PCAP validation and flow discovery'],
  ['Feature extraction', 'ESP flow statistics and inter-arrival timing'],
  ['Protocol analysis', 'RFC 4303 structural checks'],
  ['Classification', 'Backend model output and confidence'],
  ['Explanation', 'SHAP contributions and supporting evidence'],
  ['Twin verification', 'Lab replay result and generated evidence'],
]

export function AnalysisPage() {
  const [fileName, setFileName] = useState('')
  const onFileChange = (event: ChangeEvent<HTMLInputElement>) => setFileName(event.currentTarget.files?.[0]?.name ?? '')
  return (
    <div className="page-stack">
      <PageHeader eyebrow="OPERATIONS / TRAFFIC ASSESSMENT" title="PCAP analysis" description="Inspect ESP structure, extracted features, classification evidence, and verification results." actions={<StateBadge>Not started</StateBadge>} />
      <div className="analysis-layout">
        <section className="panel analysis-input-panel">
          <div className="panel-heading"><div><div className="eyebrow">INPUT</div><h2>Capture file</h2></div><LockKeyhole size={16} className="panel-heading__icon" aria-hidden="true" /></div>
          <label className="upload-zone">
            <input type="file" accept=".pcap,.pcapng,application/vnd.tcpdump.pcap" onChange={onFileChange} />
            <Upload size={20} aria-hidden="true" />
            <strong>{fileName || 'Choose a PCAP file'}</strong>
            <span>{fileName ? 'Selected locally; not uploaded' : 'PCAP / PCAPNG · File remains local until submission is enabled'}</span>
          </label>
          <div className="field-hint">File selection is local to this browser. No upload or analysis request is sent.</div>
          <button className="button button--primary button--full" type="button" disabled title="Analysis submission requires the documented backend endpoint">Start analysis</button>
          <IntegrationNotice>Analysis endpoint and response schema are not available in the supplied project.</IntegrationNotice>
        </section>
        <section className="panel pipeline-panel">
          <div className="panel-heading"><div><div className="eyebrow">ANALYSIS PIPELINE</div><h2>Processing stages</h2></div><StateBadge>Awaiting input</StateBadge></div>
          <ol className="analysis-stages">
            {analysisStages.map(([name, detail], index) => <li key={name}>
              <span className="stage-index">{String(index + 1).padStart(2, '0')}</span><span className="stage-connector" aria-hidden="true" />
              <div className="stage-copy"><strong>{name}</strong><small>{detail}</small></div><span className="stage-state">Not started</span>
            </li>)}
          </ol>
          <p className="pipeline-note">These are workflow stages, not live job state. Stage results populate only from backend responses.</p>
        </section>
      </div>
      <section className="panel explanation-panel">
        <div className="panel-heading"><div><div className="eyebrow">EXPLAINABILITY</div><h2>Classification evidence</h2></div><StateBadge>Unavailable</StateBadge></div>
        <div className="explain-grid"><div><span className="detail-label">Classification</span><strong>—</strong></div><div><span className="detail-label">Confidence</span><strong>—</strong></div><div><span className="detail-label">Feature contributions</span><strong>—</strong></div><div><span className="detail-label">Packet / flow evidence</span><strong>—</strong></div></div>
        <EmptyState title="No analysis results available" description="Feature importance, SHAP contributions, supporting packet characteristics, and verification evidence are not available until a backend analysis completes." compact />
      </section>
    </div>
  )
}

const pageDefinitions = {
  investigations: {
    eyebrow: 'OPERATIONS / TRIAGE', title: 'Investigations', description: 'Review backend-detected findings and follow each item through evidence, verification, and resolution.', emptyTitle: 'No finding data available', emptyDescription: 'Findings will be listed with severity, affected asset, detection source, protocol context, evidence, remediation, and verification status when supplied by the backend.', action: 'Open evidence', to: '/evidence', columns: ['Finding ID', 'Severity', 'Title', 'Affected asset', 'Detection source', 'Detected', 'Verification'],
  },
  verification: {
    eyebrow: 'ASSURANCE / LAB REPLAY', title: 'Verification', description: 'Track replay requests, test configuration, observed behavior, and evidence generated by the lab environment.', emptyTitle: 'No verification requests available', emptyDescription: 'Queued, running, passed, failed, and unavailable states are shown only when reported by the verification service.', action: 'View analysis workspace', to: '/analysis', columns: ['Request ID', 'Lab environment', 'Replay state', 'Expected behavior', 'Observed behavior', 'Result', 'Evidence', 'Timestamp'],
  },
  compliance: {
    eyebrow: 'ASSURANCE / CONTROL REVIEW', title: 'Compliance', description: 'Assess controls against rule packs supported by the connected backend, with linked findings and evidence.', emptyTitle: 'No compliance controls loaded', emptyDescription: 'Rule packs, control status, affected assets, findings, and remediation are not available until the backend publishes them. No compliance score is inferred.', action: 'Review evidence', to: '/evidence', columns: ['Rule pack', 'Control', 'Requirement', 'Status', 'Affected assets', 'Evidence', 'Finding', 'Remediation'],
  },
  evidence: {
    eyebrow: 'ASSURANCE / EVIDENCE RECORDS', title: 'Evidence', description: 'Inspect provenance, hashes, signatures, related findings, gateways, and verification state.', emptyTitle: 'No evidence records available', emptyDescription: 'Evidence identifiers, timestamps, hashes, signatures, and relationships are loaded from the backend only.', action: 'Open investigations', to: '/investigations', columns: ['Evidence ID', 'Source', 'Timestamp', 'Finding', 'Gateway', 'Hash', 'Signature', 'Verification'],
  },
  reports: {
    eyebrow: 'ASSURANCE / OUTPUTS', title: 'Reports', description: 'Access backend-generated security assessments, compliance reports, investigations, verification reports, and signed attestations.', emptyTitle: 'No reports available', emptyDescription: 'Report metadata is not fabricated. Generated time, scope, status, and download actions appear when returned by the reporting service.', action: 'Review compliance', to: '/compliance', columns: ['Report', 'Type', 'Scope', 'Status', 'Generated', 'Actions'],
  },
} as const

export function DataWorkspacePage({ page }: { page: keyof typeof pageDefinitions }) {
  const definition = pageDefinitions[page]
  const typeOptions = page === 'reports' ? ['All output types', 'Security assessment', 'Fleet assessment', 'Compliance report', 'Investigation report', 'Verification report', 'Signed attestation'] : page === 'compliance' ? ['All rule packs', 'RFC 4303', 'NIST', 'NSA', 'CERT-In'] : ['All statuses']
  return (
    <div className="page-stack">
      <PageHeader eyebrow={definition.eyebrow} title={definition.title} description={definition.description} actions={page === 'reports' ? <button className="button" type="button" disabled title="Report generation requires the backend reporting contract"><Clipboard size={14} /> Generate report</button> : undefined} />
      <div className="toolbar-row"><label className="field-with-icon"><span className="sr-only">Search {definition.title.toLowerCase()}</span><FileSearch size={15} aria-hidden="true" /><input type="search" placeholder={`Search ${definition.title.toLowerCase()}`} disabled /></label><label className="select-field"><Filter size={14} aria-hidden="true" /><span className="sr-only">Filter records</span><select defaultValue={typeOptions[0]} disabled>{typeOptions.map((option) => <option key={option}>{option}</option>)}</select><ChevronDown size={13} aria-hidden="true" /></label><span className="toolbar-meta">No records loaded</span></div>
      <section className="table-panel workspace-empty"><div className="data-table-wrap"><table className="data-table"><thead><tr>{definition.columns.map((column) => <th key={column}>{column}</th>)}</tr></thead><tbody><tr><td className="table-empty" colSpan={definition.columns.length}><EmptyState title={definition.emptyTitle} description={definition.emptyDescription} action={<Link to={definition.to}>{definition.action}</Link>} /></td></tr></tbody></table></div></section>
      {page === 'reports' && <section className="panel attestation-panel"><div className="panel-heading"><div><div className="eyebrow">SIGNED OUTPUT</div><h2>Attestation details</h2></div><StateBadge>Unavailable</StateBadge></div><div className="attestation-fields"><div><span>Subject</span><code>—</code></div><div><span>Timestamp</span><code>—</code></div><div><span>Signature</span><code>—</code></div><div><span>Hash</span><code>—</code></div><div><span>Verification</span><code>—</code></div><div><span>Related evidence</span><code>—</code></div></div><div className="attestation-actions"><button className="button" type="button" disabled>Verify</button><button className="button" type="button" disabled>Copy hash</button><button className="button" type="button" disabled>Download</button><Link className="subtle-link" to="/evidence">View evidence <ArrowRight size={13} /></Link><span>Requires a backend attestation record</span></div></section>}
      <IntegrationNotice />
    </div>
  )
}

export function SystemPage() {
  const configRows = [
    ['API base URL', appConfiguration.apiBaseUrl ?? 'Not configured', appConfiguration.apiConfigured ? 'Configured' : 'Unavailable'],
    ['SSE endpoint', appConfiguration.eventStreamUrl ?? 'Not configured', appConfiguration.eventsConfigured ? 'Configured · schema pending' : 'Disconnected'],
    ['Authentication issuer', appConfiguration.authIssuer ?? 'Not configured', appConfiguration.authIssuer ? 'Configured · flow pending' : 'Not configured'],
    ['Authentication client ID', appConfiguration.authClientId ?? 'Not configured', appConfiguration.authClientId ? 'Configured · flow pending' : 'Not configured'],
    ['Environment label', appConfiguration.environment, 'Display only'],
  ]
  return (
    <div className="page-stack">
      <PageHeader eyebrow="ADMINISTRATION / SERVICE CONFIGURATION" title="System" description="Review deployment-provided connection settings and integration readiness. Values are read from the build environment." />
      <section className="panel settings-panel">
        <div className="panel-heading"><div><div className="eyebrow">CONNECTION SETTINGS</div><h2>Service configuration</h2></div><StateBadge tone="warning">Contract pending</StateBadge></div>
        <div className="settings-table">{configRows.map(([label, value, state]) => <div className="settings-row" key={label}><span>{label}</span><code>{value}</code><StateBadge tone={state.includes('Configured') && !state.includes('pending') ? 'success' : 'neutral'}>{state}</StateBadge></div>)}</div>
      </section>
      <section className="panel settings-panel">
        <div className="panel-heading"><div><div className="eyebrow">INTEGRATION STATUS</div><h2>Backend capabilities</h2></div></div>
        <div className="service-list system-capabilities"><div><span>API endpoint contract</span><StateBadge tone="warning">Not supplied</StateBadge></div><div><span>Authentication protocol and permissions</span><StateBadge>Unspecified</StateBadge></div><div><span>SSE event schema</span><StateBadge>Unspecified</StateBadge></div><div><span>Role claim mapping</span><StateBadge>Unspecified</StateBadge></div><div><span>CLI companion interface</span><StateBadge>Separate interface · details pending</StateBadge></div></div>
        <p className="settings-help">The deployment environment may provide URLs, but this frontend deliberately does not call assumed endpoints or enforce unsupported role permissions. Add the backend OpenAPI specification and identity/event contracts before enabling operations.</p>
      </section>
    </div>
  )
}

export function PrivacyPage() {
  return <LegalPage title="Privacy policy" eyebrow="LEGAL / PRIVACY" />
}

export function TermsPage() {
  return <LegalPage title="Terms of use" eyebrow="LEGAL / TERMS" />
}

function LegalPage({ title, eyebrow }: { title: string; eyebrow: string }) {
  return (
    <div className="page-stack legal-page">
      <PageHeader eyebrow={eyebrow} title={title} description="Publication copy has not been provided." />
      <section className="panel legal-placeholder">
        <StateBadge tone="warning">Placeholder — replace before production</StateBadge>
        <h2>Approved legal text required</h2>
        <p>This page is intentionally a placeholder. No organization-specific privacy practices, data retention terms, warranties, or legal commitments have been invented.</p>
        <p>Replace this notice with text reviewed and approved by the responsible legal and privacy teams before deployment.</p>
      </section>
    </div>
  )
}
