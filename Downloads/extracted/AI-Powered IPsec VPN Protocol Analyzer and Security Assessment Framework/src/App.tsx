import { BrowserRouter, Route, Routes } from 'react-router-dom'
import { AppShell } from './components/AppShell'
import { OverviewPage } from './pages/OverviewPage'
import {
  AnalysisPage,
  DataWorkspacePage,
  FleetPage,
  PrivacyPage,
  ProbePage,
  SystemPage,
  TermsPage,
} from './pages/WorkspacePages'

function NotFoundPage() {
  return <div className="not-found"><span className="eyebrow">404 / PAGE NOT FOUND</span><h1>This workspace route is unavailable.</h1><a className="button" href="/">Return to overview</a></div>
}

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<AppShell />}>
          <Route index element={<OverviewPage />} />
          <Route path="fleet" element={<FleetPage />} />
          <Route path="probe" element={<ProbePage />} />
          <Route path="analysis" element={<AnalysisPage />} />
          <Route path="investigations" element={<DataWorkspacePage page="investigations" />} />
          <Route path="verification" element={<DataWorkspacePage page="verification" />} />
          <Route path="compliance" element={<DataWorkspacePage page="compliance" />} />
          <Route path="evidence" element={<DataWorkspacePage page="evidence" />} />
          <Route path="reports" element={<DataWorkspacePage page="reports" />} />
          <Route path="system" element={<SystemPage />} />
          <Route path="privacy" element={<PrivacyPage />} />
          <Route path="terms" element={<TermsPage />} />
          <Route path="*" element={<NotFoundPage />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}

export default App
