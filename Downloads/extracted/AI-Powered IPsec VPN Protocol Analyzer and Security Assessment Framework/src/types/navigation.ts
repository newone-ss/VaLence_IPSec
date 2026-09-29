export type WorkspaceRole = 'CISO' | 'Auditor' | 'Admin'

export interface NavigationItem {
  label: string
  path: string
  group: 'Operations' | 'Assurance' | 'Administration'
  description: string
}
