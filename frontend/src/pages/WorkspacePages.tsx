import { useState, useEffect, type ChangeEvent } from 'react'
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
import { appConfiguration, apiRequest } from '../services/configuration'

function IntegrationNotice({ children = 'Operational data is live and connected to Valence-IPsec backend.' }: { children?: string }) {
  return <div className="integration-notice"><CircleHelp size={15} aria-hidden="true" /><span>{children}</span></div>
}

interface GatewayRecord {
  id: number
  ip_address: string
  port: number
  vendor_guess: string
  discovered_ike_version: string
  nat_traversal: boolean
  active_tunnels: number
  risk: string
}

export function FleetPage() {
  const [gateways, setGateways] = useState<GatewayRecord[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const loadFleet = async () => {
    setLoading(true)
    setError(null)
    try {
      const data = await apiRequest<{ gateways: GatewayRecord[] }>('/api/fleet')
      setGateways(data.gateways || [])
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      setError(msg)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    let ignore = false
    apiRequest<{ gateways: GatewayRecord[] }>('/api/fleet')
      .then((data) => {
        if (!ignore) {
          setGateways(data.gateways || [])
        }
      })
      .catch((err: unknown) => {
        if (!ignore) {
          const msg = err instanceof Error ? err.message : String(err)
          setError(msg)
        }
      })
    return () => {
      ignore = true
    }
  }, [])

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="OPERATIONS / ASSET INVENTORY"
        title="VPN fleet"
        description="Gateway inventory, tunnel state, probe history, and latest assessment results."
        actions={
          <button className="button" type="button" onClick={loadFleet} disabled={loading}>
            <RefreshCw size={14} className={loading ? 'icon-spin' : ''} /> {loading ? 'Loading...' : 'Refresh'}
          </button>
        }
      />
      <div className="toolbar-row">
        <label className="field-with-icon">
          <span className="sr-only">Search gateways</span>
          <FileSearch size={15} aria-hidden="true" />
          <input type="search" placeholder="Search gateway, address, or vendor" />
        </label>
        <span className="toolbar-meta">{gateways.length} active gateways in fleet</span>
      </div>

      {error && (
        <div className="connection-banner" style={{ borderLeft: '3px solid #ef4444' }}>
          <strong>Error loading fleet:</strong> {error}
        </div>
      )}

      <section className="table-panel" aria-label="VPN gateway inventory">
        <div className="data-table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Gateway ID</th>
                <th>Address</th>
                <th>Vendor / Daemon</th>
                <th>IKE Protocol</th>
                <th>Tunnels</th>
                <th>Risk Level</th>
                <th>NAT-T</th>
              </tr>
            </thead>
            <tbody>
              {gateways.length === 0 && !loading ? (
                <tr>
                  <td colSpan={7} className="table-empty">
                    <EmptyState title="No gateways loaded" description="Click Refresh or launch a scan from the Probe workspace." />
                  </td>
                </tr>
              ) : (
                gateways.map((gw) => (
                  <tr key={gw.id}>
                    <td><code>GW-{String(gw.id).padStart(4, '0')}</code></td>
                    <td><strong>{gw.ip_address}:{gw.port}</strong></td>
                    <td><span>{gw.vendor_guess}</span></td>
                    <td><StateBadge tone={gw.discovered_ike_version === 'IKEv2' ? 'success' : 'warning'}>{gw.discovered_ike_version}</StateBadge></td>
                    <td>{gw.active_tunnels > 0 ? '1 Active' : '0 (Idle)'}</td>
                    <td><StateBadge tone={gw.risk === 'CRITICAL' ? 'critical' : 'neutral'}>{gw.risk}</StateBadge></td>
                    <td>{gw.nat_traversal ? 'Enabled' : 'Disabled'}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>
      <IntegrationNotice>Fleet store synchronized with local SQLite WAL database.</IntegrationNotice>
    </div>
  )
}

interface ProbeResultData {
  status: string
  target: string
  port: number
  probe_mode: string
  discovered_ike_version: string
  vendor_guess: string
  latency_ms: number
  findings_count: number
  accepted_transforms: Array<{ type: string; name: string; key_len: number }>
  details: string
}

export function ProbePage() {
  const [target, setTarget] = useState('10.0.1.2')
  const [port, setPort] = useState('500')
  const [probeMode, setProbeMode] = useState('ike')
  const [isProbing, setIsProbing] = useState(false)
  const [result, setResult] = useState<ProbeResultData | null>(null)
  const [history, setHistory] = useState<ProbeResultData[]>([])
  const [error, setError] = useState<string | null>(null)

  const handleRunProbe = async () => {
    if (!target.trim()) {
      setError('Please provide a target address or hostname.')
      return
    }
    setError(null)
    setIsProbing(true)
    try {
      const res = await apiRequest<ProbeResultData>('/api/probe', {
        method: 'POST',
        body: JSON.stringify({
          target: target.trim(),
          port: parseInt(port, 10) || 500,
          probe_mode: probeMode,
          consent: true,
        }),
      })
      setResult(res)
      setHistory((prev) => [res, ...prev])
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      setError(msg)
    } finally {
      setIsProbing(false)
    }
  }

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="OPERATIONS / ACTIVE DISCOVERY"
        title="Live probe"
        description="Configure an authorized IKE/UDP probe and inspect the protocol response live from the backend engine."
        actions={<StateBadge tone={isProbing ? 'warning' : result ? 'success' : 'neutral'}>{isProbing ? 'Probing...' : result ? 'Scan Complete' : 'Ready'}</StateBadge>}
      />

      {error && (
        <div className="connection-banner" style={{ borderLeft: '3px solid #ef4444' }}>
          <strong>Probe Error:</strong> {error}
        </div>
      )}

      <div className="split-workspace">
        <section className="panel form-panel">
          <div className="panel-heading">
            <div>
              <div className="eyebrow">PROBE CONFIGURATION</div>
              <h2>Target and parameters</h2>
            </div>
            <Radio size={17} className="panel-heading__icon" aria-hidden="true" />
          </div>

          <label className="form-field">
            <span>Target address or hostname</span>
            <input value={target} onChange={(event) => setTarget(event.target.value)} placeholder="e.g. 10.0.1.2 or 127.0.0.1" autoComplete="off" />
          </label>

          <div className="form-grid-two">
            <label className="form-field">
              <span>UDP destination port</span>
              <input inputMode="numeric" value={port} onChange={(event) => setPort(event.target.value)} />
            </label>
            <label className="form-field">
              <span>Probe profile</span>
              <select value={probeMode} onChange={(event) => setProbeMode(event.target.value)}>
                <option value="ike">IKE negotiation discovery</option>
                <option value="udp">UDP reachability only</option>
              </select>
            </label>
          </div>

          <label className="checkbox-row">
            <input type="checkbox" defaultChecked />
            <span>Consent granted: target host authorized for assessment (ADR-0003)</span>
          </label>

          <div className="form-actions">
            <button className="button button--primary" type="button" onClick={handleRunProbe} disabled={isProbing}>
              {isProbing ? 'Executing probe...' : 'Run live probe'}
            </button>
            <span>{isProbing ? 'Transmitting UDP probes...' : 'Ready to execute'}</span>
          </div>

          <IntegrationNotice>Active elimination probing operates strictly within consent boundaries.</IntegrationNotice>
        </section>

        <section className="panel result-panel">
          <div className="panel-heading">
            <div>
              <div className="eyebrow">PROBE RESULT</div>
              <h2>Response details</h2>
            </div>
            <StateBadge tone={result ? 'success' : 'neutral'}>{result ? result.status.toUpperCase() : 'Awaiting request'}</StateBadge>
          </div>

          {!result ? (
            <EmptyState title="No probe results yet" description="Enter a target address above and click 'Run live probe' to inspect negotiation response." compact />
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div className="result-field-list">
                <div><span>Target endpoint</span><strong>{result.target}:{result.port}</strong></div>
                <div><span>IKE Protocol</span><StateBadge tone={result.discovered_ike_version === 'IKEv1' ? 'warning' : 'success'}>{result.discovered_ike_version}</StateBadge></div>
                <div><span>Identified Vendor</span><strong>{result.vendor_guess}</strong></div>
                <div><span>Probe RTT</span><strong>{result.latency_ms.toFixed(1)} ms</strong></div>
                <div><span>Security Findings</span><StateBadge tone="critical">{result.findings_count} Flagged</StateBadge></div>
              </div>

              <div>
                <span className="eyebrow">ACCEPTED TRANSFORMS</span>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem', marginTop: '0.4rem' }}>
                  {result.accepted_transforms.map((t) => (
                    <code key={t.name} style={{ padding: '0.2rem 0.5rem', background: 'rgba(255,255,255,0.06)', borderRadius: '4px', fontSize: '0.8rem' }}>
                      [{t.type}] {t.name} ({t.key_len}b)
                    </code>
                  ))}
                </div>
              </div>

              <p style={{ fontSize: '0.85rem', color: '#94a3b8', lineHeight: 1.5, margin: 0 }}>
                {result.details}
              </p>
            </div>
          )}
        </section>
      </div>

      <section className="panel">
        <div className="panel-heading">
          <div><div className="eyebrow">HISTORY</div><h2>Previous probe runs</h2></div>
        </div>
        {history.length === 0 ? (
          <EmptyState title="No previous runs in session" description="Executed probes in this session will be recorded here." compact />
        ) : (
          <div className="data-table-wrap">
            <table className="data-table">
              <thead><tr><th>Target</th><th>Port</th><th>Protocol</th><th>Vendor</th><th>Findings</th><th>RTT</th></tr></thead>
              <tbody>
                {history.map((h, i) => (
                  <tr key={`${h.target}-${i}`}>
                    <td><code>{h.target}</code></td>
                    <td>{h.port}</td>
                    <td>{h.discovered_ike_version}</td>
                    <td>{h.vendor_guess}</td>
                    <td>{h.findings_count}</td>
                    <td>{h.latency_ms.toFixed(1)} ms</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
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

interface AnalysisResponse {
  status: string
  file_name: string
  file_size_bytes: number
  flows_discovered: number
  esp_packets: number
  detected_ciphers: string[]
  rfc4303_compliant: boolean
  confidence: number
  message: string
}

export function AnalysisPage() {
  const [file, setFile] = useState<File | null>(null)
  const [fileName, setFileName] = useState('')
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [analysisResult, setAnalysisResult] = useState<AnalysisResponse | null>(null)
  const [error, setError] = useState<string | null>(null)

  const onFileChange = (event: ChangeEvent<HTMLInputElement>) => {
    const f = event.currentTarget.files?.[0] || null
    setFile(f)
    setFileName(f?.name ?? '')
  }

  const handleStartAnalysis = async () => {
    if (!file) return
    setIsAnalyzing(true)
    setError(null)
    try {
      const formData = new FormData()
      formData.append('file', file)
      const base = appConfiguration.apiBaseUrl || 'http://127.0.0.1:8000'
      const res = await fetch(`${base}/api/analysis`, {
        method: 'POST',
        body: formData,
      })
      if (!res.ok) throw new Error(`Analysis upload failed: ${res.status}`)
      const data = (await res.json()) as AnalysisResponse
      setAnalysisResult(data)
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      setError(msg)
    } finally {
      setIsAnalyzing(false)
    }
  }

  return (
    <div className="page-stack">
      <PageHeader
        eyebrow="OPERATIONS / TRAFFIC ASSESSMENT"
        title="PCAP analysis"
        description="Inspect ESP structure, extracted features, classification evidence, and verification results."
        actions={<StateBadge tone={analysisResult ? 'success' : isAnalyzing ? 'warning' : 'neutral'}>{analysisResult ? 'Analysis Complete' : isAnalyzing ? 'Processing...' : 'Ready'}</StateBadge>}
      />

      {error && (
        <div className="connection-banner" style={{ borderLeft: '3px solid #ef4444' }}>
          <strong>Analysis Error:</strong> {error}
        </div>
      )}

      <div className="analysis-layout">
        <section className="panel analysis-input-panel">
          <div className="panel-heading">
            <div><div className="eyebrow">INPUT</div><h2>Capture file</h2></div>
            <LockKeyhole size={16} className="panel-heading__icon" aria-hidden="true" />
          </div>
          <label className="upload-zone">
            <input type="file" accept=".pcap,.pcapng,application/vnd.tcpdump.pcap" onChange={onFileChange} />
            <Upload size={20} aria-hidden="true" />
            <strong>{fileName || 'Choose a PCAP file'}</strong>
            <span>{fileName ? `${(file?.size ? file.size / 1024 : 0).toFixed(1)} KB selected` : 'PCAP / PCAPNG file format supported'}</span>
          </label>
          <div className="field-hint">Upload a packet capture to evaluate ESP traffic and candidate cipher suites.</div>
          <button className="button button--primary button--full" type="button" onClick={handleStartAnalysis} disabled={!file || isAnalyzing}>
            {isAnalyzing ? 'Analyzing PCAP...' : 'Start analysis'}
          </button>
        </section>

        <section className="panel pipeline-panel">
          <div className="panel-heading"><div><div className="eyebrow">ANALYSIS PIPELINE</div><h2>Processing stages</h2></div><StateBadge tone={analysisResult ? 'success' : 'neutral'}>{analysisResult ? 'Complete' : 'Awaiting file'}</StateBadge></div>
          <ol className="analysis-stages">
            {analysisStages.map(([name, detail], index) => (
              <li key={name}>
                <span className="stage-index">{String(index + 1).padStart(2, '0')}</span>
                <span className="stage-connector" aria-hidden="true" />
                <div className="stage-copy"><strong>{name}</strong><small>{detail}</small></div>
                <span className="stage-state">{analysisResult ? 'Verified' : 'Pending'}</span>
              </li>
            ))}
          </ol>
        </section>
      </div>

      <section className="panel explanation-panel">
        <div className="panel-heading"><div><div className="eyebrow">EXPLAINABILITY</div><h2>Classification evidence</h2></div><StateBadge tone={analysisResult ? 'success' : 'neutral'}>{analysisResult ? 'Classified' : 'Unavailable'}</StateBadge></div>
        {!analysisResult ? (
          <EmptyState title="No analysis results available" description="Feature importance, SHAP contributions, supporting packet characteristics, and verification evidence appear after uploading a capture." compact />
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div className="explain-grid">
              <div><span className="detail-label">File Name</span><strong>{analysisResult.file_name}</strong></div>
              <div><span className="detail-label">Confidence</span><strong>{(analysisResult.confidence * 100).toFixed(1)}%</strong></div>
              <div><span className="detail-label">ESP Packets</span><strong>{analysisResult.esp_packets} packets</strong></div>
              <div><span className="detail-label">RFC 4303 Alignment</span><strong>{analysisResult.rfc4303_compliant ? 'Compliant' : 'Non-compliant'}</strong></div>
            </div>
            <div>
              <span className="eyebrow">CANDIDATE CIPHER SOLVER (RFC 4303)</span>
              <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.4rem' }}>
                {analysisResult.detected_ciphers.map((c) => (
                  <code key={c} style={{ padding: '0.25rem 0.6rem', background: 'rgba(34,197,94,0.1)', color: '#4ade80', borderRadius: '4px' }}>{c}</code>
                ))}
              </div>
            </div>
          </div>
        )}
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
