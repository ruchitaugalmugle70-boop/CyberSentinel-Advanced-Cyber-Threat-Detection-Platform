import { useState } from 'react';

const navItems = [
  { id: 'dashboard', icon: '📊', label: 'Dashboard', badge: null },
  { id: 'spyware', icon: '🔍', label: 'Spyware Scanner', badge: null },
  { id: 'sqli', icon: '💉', label: 'SQL Injection', badge: null },
  { id: 'repo', icon: '📦', label: 'Repo Security', badge: null },
  { id: 'network', icon: '🌐', label: 'Network Monitor', badge: null },
  { id: 'mitre', icon: '🎯', label: 'MITRE ATT&CK', badge: 'NEW' },
  { id: 'compliance', icon: '📜', label: 'STIX Exporter', badge: 'NEW' },
  { id: 'yara', icon: '🔬', label: 'YARA Sandbox', badge: 'NEW' },
  { id: 'playbooks', icon: '⚡', label: 'Playbooks', badge: 'NEW' },
];

const bottomNavItems = [
  { id: 'system_audit', icon: '🛡️', label: 'System Audit', badge: null },
  { id: 'alerts', icon: '🔔', label: 'Alert History', badge: '12' },
  { id: 'settings', icon: '⚙️', label: 'Settings', badge: null },
];

export default function Sidebar({ activeTab, onTabChange }) {
  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <div className="brand-icon">🛡️</div>
        <div>
          <h1>CYBERSENTINEL</h1>
          <div className="brand-tag">Threat Defense Suite v2.0</div>
        </div>
      </div>

      <nav className="sidebar-nav">
        <div className="nav-section-label">Defense Modules</div>
        {navItems.map((item) => (
          <div
            key={item.id}
            className={`nav-item ${activeTab === item.id ? 'active' : ''}`}
            onClick={() => onTabChange(item.id)}
          >
            <span className="nav-icon">{item.icon}</span>
            <span>{item.label}</span>
            {item.badge && <span className="nav-badge">{item.badge}</span>}
          </div>
        ))}

        <div className="nav-section-label font-bold text-xs uppercase tracking-wider text-muted mt-4 mb-2">Platform Administration</div>
        {bottomNavItems.map((item) => (
          <div
            key={item.id}
            className={`nav-item ${activeTab === item.id ? 'active' : ''}`}
            onClick={() => onTabChange(item.id)}
          >
            <span className="nav-icon">{item.icon}</span>
            <span>{item.label}</span>
            {item.badge && <span className="nav-badge">{item.badge}</span>}
          </div>
        ))}
      </nav>

      <div className="sidebar-footer">
        <div className="system-status">
          <div className="status-dot"></div>
          <div>
            <div className="status-text">All Engines Active</div>
            <div className="status-sub">9 defense modules active</div>
          </div>
        </div>
      </div>
    </aside>
  );
}
