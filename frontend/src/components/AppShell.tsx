import { useEffect, useState } from 'react'
import { NavLink, Outlet, useLocation } from 'react-router-dom'
import {
  Activity,
  AlertTriangle,
  BadgeCheck,
  ChevronDown,
  CircleHelp,
  ClipboardCheck,
  FileBarChart2,
  FileSearch,
  Fingerprint,
  Gauge,
  Menu,
  Radio,
  Search,
  ServerCog,
  Shield,
  ShieldAlert,
  Moon,
  Sun,
  UserRound,
  X,
} from 'lucide-react'
import { appConfiguration } from '../services/configuration'
import type { NavigationItem } from '../types/navigation'

const navigation: NavigationItem[] = [
  { label: 'Overview', path: '/', group: 'Operations', description: 'Operational state' },
  { label: 'VPN fleet', path: '/fleet', group: 'Operations', description: 'Gateway inventory' },
  { label: 'Live probe', path: '/probe', group: 'Operations', description: 'IKE and UDP probe' },
  { label: 'PCAP analysis', path: '/analysis', group: 'Operations', description: 'Traffic assessment' },
  { label: 'Investigations', path: '/investigations', group: 'Operations', description: 'Security findings' },
  { label: 'Verification', path: '/verification', group: 'Assurance', description: 'Lab replay' },
  { label: 'Compliance', path: '/compliance', group: 'Assurance', description: 'Controls and rule packs' },
  { label: 'Evidence', path: '/evidence', group: 'Assurance', description: 'Evidence records' },
  { label: 'Reports', path: '/reports', group: 'Assurance', description: 'Assessments and attestations' },
  { label: 'System', path: '/system', group: 'Administration', description: 'Service configuration' },
]

const iconByLabel = {
  Overview: Gauge,
  'VPN fleet': ServerCog,
  'Live probe': Radio,
  'PCAP analysis': Activity,
  Investigations: FileSearch,
  Verification: BadgeCheck,
  Compliance: ClipboardCheck,
  Evidence: Fingerprint,
  Reports: FileBarChart2,
  System: Shield,
}

const groups: NavigationItem['group'][] = ['Operations', 'Assurance', 'Administration']
type ColorTheme = 'dark' | 'light'
const themeStorageKey = 'ipsec-color-theme'

function readTheme(): ColorTheme {
  try {
    return localStorage.getItem(themeStorageKey) === 'light' ? 'light' : 'dark'
  } catch {
    return 'dark'
  }
}

export function AppShell() {
  const [mobileOpen, setMobileOpen] = useState(false)
  const [theme, setTheme] = useState<ColorTheme>(readTheme)
  const location = useLocation()
  const activePage = navigation.find((item) => item.path === location.pathname)
  const apiConfigured = appConfiguration.apiConfigured

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    document.documentElement.style.colorScheme = theme
    try {
      localStorage.setItem(themeStorageKey, theme)
    } catch {
      // Theme preference remains functional for the current session.
    }
  }, [theme])

  return (
    <div className="app-frame">
      <aside className={`sidebar${mobileOpen ? ' sidebar--open' : ''}`} aria-label="Primary navigation">
        <div className="brand-lockup">
          <div className="brand-mark" aria-hidden="true"><Shield size={19} strokeWidth={1.8} /></div>
          <div className="brand-text"><span>IPSEC</span><small>SECURITY ASSESSMENT</small></div>
          <button className="icon-button sidebar-close" type="button" aria-label="Close navigation" onClick={() => setMobileOpen(false)}><X size={17} /></button>
        </div>

        <div className="workspace-switcher">
          <div className="workspace-icon"><ShieldAlert size={15} aria-hidden="true" /></div>
          <div className="workspace-copy"><span>Assessment workspace</span><small>{appConfiguration.environment}</small></div>
          <ChevronDown size={14} className="muted-icon" aria-hidden="true" />
        </div>

        <nav className="nav-groups">
          {groups.map((group) => (
            <section className="nav-group" key={group} aria-label={group}>
              <h2>{group}</h2>
              {navigation.filter((item) => item.group === group).map((item) => {
                const Icon = iconByLabel[item.label as keyof typeof iconByLabel]
                return (
                  <NavLink
                    key={item.path}
                    to={item.path}
                    end={item.path === '/'}
                    className={({ isActive }) => `nav-link${isActive ? ' nav-link--active' : ''}`}
                    onClick={() => setMobileOpen(false)}
                    title={item.description}
                  >
                    <Icon size={16} strokeWidth={1.8} aria-hidden="true" />
                    <span>{item.label}</span>
                  </NavLink>
                )
              })}
            </section>
          ))}
        </nav>

        <div className="sidebar-bottom">
          <div className="sidebar-service-label"><span className={`service-dot${apiConfigured ? ' service-dot--configured' : ''}`} />
            <span>{apiConfigured ? 'API URL configured' : 'Backend not connected'}</span>
          </div>
          <div className="legal-links"><NavLink to="/privacy">Privacy</NavLink><span aria-hidden="true">·</span><NavLink to="/terms">Terms</NavLink></div>
          <p className="sidebar-version">Security operations console</p>
        </div>
      </aside>

      {mobileOpen && <button className="sidebar-backdrop" type="button" aria-label="Close navigation" onClick={() => setMobileOpen(false)} />}

      <div className="main-column">
        <header className="topbar">
          <div className="topbar-left">
            <button className="icon-button mobile-menu" type="button" aria-label="Open navigation" onClick={() => setMobileOpen(true)}><Menu size={19} /></button>
            <div className="breadcrumb"><span>Security assessment</span><span className="breadcrumb-separator">/</span><strong>{activePage?.label ?? (location.pathname === '/privacy' ? 'Privacy' : location.pathname === '/terms' ? 'Terms' : 'Workspace')}</strong></div>
          </div>
          <div className="topbar-right">
            <div className="topbar-search" aria-label="Global search unavailable">
              <Search size={15} aria-hidden="true" />
              <span>Global search unavailable</span>
            </div>
            <div className="topbar-status"><span className={`service-dot${apiConfigured ? ' service-dot--configured' : ''}`} /><span>{apiConfigured ? 'API URL set' : 'Disconnected'}</span></div>
            <button
              type="button"
              className="icon-button theme-toggle"
              aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
              title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
              onClick={() => setTheme((current) => {
                const nextTheme = current === 'dark' ? 'light' : 'dark'
                try {
                  localStorage.setItem(themeStorageKey, nextTheme)
                } catch {
                  // Theme preference remains functional for the current session.
                }
                return nextTheme
              })}
            >
              {theme === 'dark' ? <Sun size={16} aria-hidden="true" /> : <Moon size={16} aria-hidden="true" />}
            </button>
            <button type="button" className="icon-button help-button" aria-label="Help and documentation" title="Help and documentation are not configured"><CircleHelp size={17} /></button>
            <div className="identity-context" title="Identity integration is not configured">
              <div className="identity-icon"><UserRound size={15} aria-hidden="true" /></div>
              <div><strong>Identity</strong><small>Not configured</small></div>
            </div>
          </div>
        </header>
        <main className="main-content" id="main-content">
          <Outlet />
        </main>
        <footer className="app-footer">
          <span><AlertTriangle size={13} aria-hidden="true" /> Backend contract not supplied — operational data is unavailable.</span>
          <span className="footer-context"><span>Environment</span><strong>{appConfiguration.environment}</strong></span>
        </footer>
      </div>
    </div>
  )
}
