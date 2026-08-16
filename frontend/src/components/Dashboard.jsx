import { useState, useEffect, useRef, useCallback } from 'react';
import ThreatMap from './ThreatMap';
import {
  generateAlert,
  getDashboardStats,
  getThreatTrendData,
  getAttackTypeDistribution,
  SEVERITY_LEVELS,
} from '../utils/threatData';

function StatCard({ icon, iconClass, label, value, trend, trendDir, delay }) {
  return (
    <div className={`stat-card animate-fade-in-up stagger-${delay}`}>
      <div className="card-header">
        <div className={`card-icon ${iconClass}`}>{icon}</div>
        <span className={`card-trend ${trendDir === 'up' ? 'up' : 'down'}`}>
          {trend}
        </span>
      </div>
      <div className="card-value">{typeof value === 'number' ? value.toLocaleString() : value}</div>
      <div className="card-label">{label}</div>
    </div>
  );
}

function SecurityGauge({ score }) {
  const circumference = 2 * Math.PI * 65;
  const offset = circumference - (score / 100) * circumference;
  const color =
    score >= 80 ? 'var(--green)' : score >= 60 ? 'var(--amber)' : 'var(--red)';

  return (
    <div className="security-gauge">
      <div className="gauge-ring">
        <svg viewBox="0 0 160 160">
          <circle className="gauge-bg" cx="80" cy="80" r="65" />
          <circle
            className="gauge-fill"
            cx="80"
            cy="80"
            r="65"
            stroke={color}
            strokeDasharray={circumference}
            strokeDashoffset={offset}
          />
        </svg>
        <div className="gauge-score">
          <span className="score-value" style={{ color }}>
            {score}
          </span>
          <span className="score-label">Security Score</span>
        </div>
      </div>
    </div>
  );
}

function ThreatTrendChart() {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const data = getThreatTrendData();
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.parentElement.getBoundingClientRect();
    const w = rect.width;
    const h = 180;
    canvas.width = w * dpr;
    canvas.height = h * dpr;
    canvas.style.width = w + 'px';
    canvas.style.height = h + 'px';
    ctx.scale(dpr, dpr);

    const paddingLeft = 36;
    const paddingBottom = 28;
    const paddingTop = 10;
    const chartW = w - paddingLeft - 10;
    const chartH = h - paddingBottom - paddingTop;

    const maxVal = Math.max(...data.datasets.flatMap((d) => d.data));
    const stepX = chartW / (data.labels.length - 1);

    // Grid lines
    ctx.strokeStyle = 'rgba(255,255,255,0.04)';
    ctx.lineWidth = 1;
    for (let i = 0; i <= 4; i++) {
      const y = paddingTop + (chartH / 4) * i;
      ctx.beginPath();
      ctx.moveTo(paddingLeft, y);
      ctx.lineTo(w - 10, y);
      ctx.stroke();

      ctx.fillStyle = 'rgba(255,255,255,0.25)';
      ctx.font = '10px JetBrains Mono, monospace';
      ctx.textAlign = 'right';
      ctx.fillText(Math.round(maxVal - (maxVal / 4) * i), paddingLeft - 6, y + 3);
    }

    // Labels
    ctx.fillStyle = 'rgba(255,255,255,0.3)';
    ctx.font = '10px JetBrains Mono, monospace';
    ctx.textAlign = 'center';
    data.labels.forEach((label, i) => {
      ctx.fillText(label, paddingLeft + i * stepX, h - 6);
    });

    // Lines
    data.datasets.forEach((dataset) => {
      ctx.beginPath();
      dataset.data.forEach((val, i) => {
        const x = paddingLeft + i * stepX;
        const y = paddingTop + chartH - (val / maxVal) * chartH;
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      });
      ctx.strokeStyle = dataset.color;
      ctx.lineWidth = 2;
      ctx.stroke();

      // Area fill
      const lastX = paddingLeft + (dataset.data.length - 1) * stepX;
      ctx.lineTo(lastX, paddingTop + chartH);
      ctx.lineTo(paddingLeft, paddingTop + chartH);
      ctx.closePath();
      const gradient = ctx.createLinearGradient(0, paddingTop, 0, paddingTop + chartH);
      gradient.addColorStop(0, dataset.color.replace(')', ', 0.15)').replace('rgb', 'rgba'));
      gradient.addColorStop(1, 'transparent');
      ctx.fillStyle = gradient;
      ctx.fill();

      // Dots
      dataset.data.forEach((val, i) => {
        const x = paddingLeft + i * stepX;
        const y = paddingTop + chartH - (val / maxVal) * chartH;
        ctx.beginPath();
        ctx.arc(x, y, 3, 0, Math.PI * 2);
        ctx.fillStyle = dataset.color;
        ctx.fill();
      });
    });
  }, []);

  return <canvas ref={canvasRef} style={{ width: '100%' }} />;
}

function AttackDistributionChart() {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const data = getAttackTypeDistribution();
    const dpr = window.devicePixelRatio || 1;
    const size = 160;
    canvas.width = size * dpr;
    canvas.height = size * dpr;
    canvas.style.width = size + 'px';
    canvas.style.height = size + 'px';
    ctx.scale(dpr, dpr);

    const total = data.reduce((sum, d) => sum + d.value, 0);
    const cx = size / 2;
    const cy = size / 2;
    const outerR = 68;
    const innerR = 42;

    let startAngle = -Math.PI / 2;
    data.forEach((item) => {
      const sliceAngle = (item.value / total) * Math.PI * 2;
      ctx.beginPath();
      ctx.arc(cx, cy, outerR, startAngle, startAngle + sliceAngle);
      ctx.arc(cx, cy, innerR, startAngle + sliceAngle, startAngle, true);
      ctx.closePath();
      ctx.fillStyle = item.color;
      ctx.fill();
      startAngle += sliceAngle;
    });

    // Center text
    ctx.fillStyle = '#e8ecf4';
    ctx.font = 'bold 20px Orbitron, sans-serif';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(total, cx, cy - 6);
    ctx.font = '9px JetBrains Mono, monospace';
    ctx.fillStyle = 'rgba(255,255,255,0.4)';
    ctx.fillText('THREATS', cx, cy + 12);
  }, []);

  const data = getAttackTypeDistribution();

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 16 }}>
      <canvas ref={canvasRef} />
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px 14px', justifyContent: 'center' }}>
        {data.map((item) => (
          <div key={item.label} className="legend-item">
            <div className="legend-dot" style={{ background: item.color }} />
            <span style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>{item.label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function AlertItem({ alert, index }) {
  const timeAgo = (date) => {
    const seconds = Math.floor((Date.now() - new Date(date).getTime()) / 1000);
    if (seconds < 60) return `${seconds}s ago`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    return `${Math.floor(seconds / 3600)}h ago`;
  };

  return (
    <div className="alert-item animate-slide-in" style={{ animationDelay: `${index * 50}ms` }}>
      <div className={`alert-severity ${alert.severity}`} />
      <div className="alert-content">
        <div className="alert-message">{alert.message}</div>
        <div className="alert-meta">
          <span className="alert-time">{timeAgo(alert.timestamp)}</span>
          <span className={`alert-tag ${alert.category}`}>{alert.category.toUpperCase()}</span>
          <span className="alert-time">src: {alert.source}</span>
        </div>
      </div>
    </div>
  );
}

export default function Dashboard() {
  const stats = getDashboardStats();
  const [alerts, setAlerts] = useState(() => {
    const initial = [];
    for (let i = 0; i < 6; i++) {
      const a = generateAlert();
      a.timestamp = new Date(Date.now() - (i + 1) * 15000);
      initial.push(a);
    }
    return initial;
  });

  useEffect(() => {
    const interval = setInterval(() => {
      setAlerts((prev) => [generateAlert(), ...prev].slice(0, 50));
    }, 4000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="page-content">
      {/* Stat Cards */}
      <div className="stat-cards">
        <StatCard icon="🎯" iconClass="red" label="Threats Detected" value={stats.threatsDetected.value} trend={stats.threatsDetected.trend} trendDir="up" delay={1} />
        <StatCard icon="🔄" iconClass="cyan" label="Active Scans" value={stats.activeScans.value} trend={stats.activeScans.trend} trendDir="down" delay={2} />
        <StatCard icon="🛡️" iconClass="green" label="Security Score" value={`${stats.securityScore.value}/100`} trend={stats.securityScore.trend} trendDir="down" delay={3} />
        <StatCard icon="⚠️" iconClass="amber" label="Vulnerabilities" value={stats.vulnerabilities.value} trend={stats.vulnerabilities.trend} trendDir="down" delay={4} />
      </div>

      {/* Main Grid */}
      <div className="dashboard-grid">
        {/* Left Column */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          {/* Threat Map */}
          <div className="panel animate-fade-in-up" style={{ animationDelay: '0.25s', opacity: 0 }}>
            <div className="panel-header">
              <div className="panel-title">
                <span className="title-icon">🌍</span>
                Global Threat Map
              </div>
              <div className="panel-actions">
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.65rem', color: 'var(--green)', display: 'flex', alignItems: 'center', gap: 6 }}>
                  <span className="status-dot" style={{ width: 6, height: 6 }} />
                  LIVE
                </span>
              </div>
            </div>
            <ThreatMap />
          </div>

          {/* Threat Trend Chart */}
          <div className="panel animate-fade-in-up" style={{ animationDelay: '0.35s', opacity: 0 }}>
            <div className="panel-header">
              <div className="panel-title">
                <span className="title-icon">📈</span>
                Threat Trends (7-Day)
              </div>
            </div>
            <div className="panel-body">
              <ThreatTrendChart />
              <div style={{ display: 'flex', gap: 16, justifyContent: 'center', marginTop: 14 }}>
                {getThreatTrendData().datasets.map((d) => (
                  <div key={d.label} className="legend-item">
                    <div className="legend-dot" style={{ background: d.color }} />
                    <span style={{ fontSize: '0.7rem' }}>{d.label}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Right Column */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          {/* Security Score */}
          <div className="panel animate-fade-in-up" style={{ animationDelay: '0.3s', opacity: 0 }}>
            <div className="panel-header">
              <div className="panel-title">
                <span className="title-icon">🛡️</span>
                Security Score
              </div>
            </div>
            <SecurityGauge score={stats.securityScore.value} />
          </div>

          {/* Attack Distribution */}
          <div className="panel animate-fade-in-up" style={{ animationDelay: '0.35s', opacity: 0 }}>
            <div className="panel-header">
              <div className="panel-title">
                <span className="title-icon">🥧</span>
                Attack Distribution
              </div>
            </div>
            <div className="panel-body">
              <AttackDistributionChart />
            </div>
          </div>

          {/* Live Alert Feed */}
          <div className="panel animate-fade-in-up" style={{ animationDelay: '0.4s', opacity: 0 }}>
            <div className="panel-header">
              <div className="panel-title">
                <span className="title-icon">🔔</span>
                Live Alerts
              </div>
              <span className="results-count">{alerts.length}</span>
            </div>
            <div className="alert-feed">
              {alerts.slice(0, 10).map((alert, i) => (
                <AlertItem key={alert.id} alert={alert} index={i} />
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
