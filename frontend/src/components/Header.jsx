export default function Header({ activeTab }) {
  const pageTitles = {
    dashboard: 'Threat Dashboard',
    spyware: 'Spyware & IOC Scanner',
    sqli: 'SQL Injection Scanner',
    repo: 'Repository Security',
    network: 'Network Monitor',
    alerts: 'Alert History',
    settings: 'Settings',
  };

  const pageBadges = {
    dashboard: 'LIVE',
    spyware: 'IOC ENGINE',
    sqli: 'DAST',
    repo: 'SAST',
    network: 'MONITOR',
    alerts: 'HISTORY',
    settings: 'CONFIG',
  };

  return (
    <header className="header">
      <div className="header-left">
        <h2>{pageTitles[activeTab] || 'Dashboard'}</h2>
        <span className="page-badge">{pageBadges[activeTab] || 'LIVE'}</span>
      </div>

      <div className="header-right">
        <div className="header-search">
          <span className="search-icon">🔎</span>
          <input type="text" placeholder="Search threats, IPs, domains..." />
        </div>

        <button className="header-btn" title="Notifications">
          🔔
          <span className="notif-dot"></span>
        </button>

        <button className="header-btn" title="Full Scan">
          🚀
        </button>

        <button className="header-btn" title="User">
          👤
        </button>
      </div>
    </header>
  );
}
