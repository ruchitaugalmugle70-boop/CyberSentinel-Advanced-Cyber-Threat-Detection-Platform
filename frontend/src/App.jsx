import { useState } from 'react';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import Dashboard from './components/Dashboard';
import SpywareScanner from './components/SpywareScanner';
import SQLInjectionScanner from './components/SQLInjectionScanner';
import RepoSecurityScanner from './components/RepoSecurityScanner';
import NetworkMonitor from './components/NetworkMonitor';
import AlertHistory from './components/AlertHistory';
import Settings from './components/Settings';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');

  const renderActiveModule = () => {
    switch (activeTab) {
      case 'dashboard':
        return <Dashboard />;
      case 'spyware':
        return <SpywareScanner />;
      case 'sqli':
        return <SQLInjectionScanner />;
      case 'repo':
        return <RepoSecurityScanner />;
      case 'network':
        return <NetworkMonitor />;
      case 'alerts':
        return <AlertHistory />;
      case 'settings':
        return <Settings />;
      default:
        return <Dashboard />;
    }
  };

  return (
    <div className="app-layout">
      {/* Dynamic Cyberpunk Ambient Effects */}
      <div className="matrix-bg" />
      <div className="grid-overlay" />

      {/* Navigation & Shell */}
      <Sidebar activeTab={activeTab} onTabChange={setActiveTab} />

      {/* Main Panel */}
      <main className="main-content">
        <Header activeTab={activeTab} />
        {renderActiveModule()}
      </main>
    </div>
  );
}
