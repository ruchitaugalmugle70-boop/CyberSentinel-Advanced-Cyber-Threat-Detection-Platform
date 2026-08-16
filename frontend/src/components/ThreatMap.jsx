import { useEffect, useRef } from 'react';
import { ATTACK_ORIGINS } from '../utils/threatData';

export default function ThreatMap() {
  const canvasRef = useRef(null);
  const animRef = useRef(null);
  const attackLines = useRef([]);

  useEffect(() => {
    const canvas = canvasRef.current;
    const ctx = canvas.getContext('2d');
    let width, height;

    function resize() {
      const rect = canvas.parentElement.getBoundingClientRect();
      width = rect.width;
      height = rect.height;
      canvas.width = width * window.devicePixelRatio;
      canvas.height = height * window.devicePixelRatio;
      canvas.style.width = width + 'px';
      canvas.style.height = height + 'px';
      ctx.scale(window.devicePixelRatio, window.devicePixelRatio);
    }
    resize();
    window.addEventListener('resize', resize);

    // Convert lat/lng to x/y on our map (simple Mercator)
    function latLngToXY(lat, lng) {
      const x = ((lng + 180) / 360) * width;
      const y = ((90 - lat) / 180) * height;
      return { x, y };
    }

    // Our defense center (New York area)
    const center = latLngToXY(40.71, -74.01);

    // Draw world grid lines
    function drawGrid() {
      ctx.strokeStyle = 'rgba(0, 240, 255, 0.04)';
      ctx.lineWidth = 0.5;
      // Latitude lines
      for (let lat = -60; lat <= 80; lat += 20) {
        const y = ((90 - lat) / 180) * height;
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(width, y);
        ctx.stroke();
      }
      // Longitude lines
      for (let lng = -180; lng <= 180; lng += 30) {
        const x = ((lng + 180) / 360) * width;
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, height);
        ctx.stroke();
      }
    }

    // Draw dots representing rough landmasses
    function drawLandDots() {
      ctx.fillStyle = 'rgba(0, 240, 255, 0.06)';
      // Simplified continent outlines as dots
      const landPoints = [
        // North America
        ...Array.from({ length: 30 }, () => ({ lat: 35 + Math.random() * 25, lng: -120 + Math.random() * 60 })),
        // South America
        ...Array.from({ length: 20 }, () => ({ lat: -30 + Math.random() * 40, lng: -75 + Math.random() * 30 })),
        // Europe
        ...Array.from({ length: 20 }, () => ({ lat: 42 + Math.random() * 20, lng: -10 + Math.random() * 40 })),
        // Africa
        ...Array.from({ length: 25 }, () => ({ lat: -20 + Math.random() * 50, lng: -15 + Math.random() * 50 })),
        // Asia
        ...Array.from({ length: 35 }, () => ({ lat: 20 + Math.random() * 40, lng: 60 + Math.random() * 80 })),
        // Australia
        ...Array.from({ length: 10 }, () => ({ lat: -35 + Math.random() * 15, lng: 120 + Math.random() * 30 })),
      ];

      landPoints.forEach((p) => {
        const { x, y } = latLngToXY(p.lat, p.lng);
        ctx.beginPath();
        ctx.arc(x, y, 2, 0, Math.PI * 2);
        ctx.fill();
      });
    }

    // Draw attack origin nodes
    function drawNodes(time) {
      ATTACK_ORIGINS.forEach((origin, i) => {
        const pos = latLngToXY(origin.lat, origin.lng);
        const pulse = Math.sin(time * 0.003 + i) * 0.5 + 0.5;

        // Outer glow
        const gradient = ctx.createRadialGradient(pos.x, pos.y, 0, pos.x, pos.y, 12 + pulse * 6);
        gradient.addColorStop(0, 'rgba(255, 51, 102, 0.4)');
        gradient.addColorStop(1, 'rgba(255, 51, 102, 0)');
        ctx.fillStyle = gradient;
        ctx.beginPath();
        ctx.arc(pos.x, pos.y, 12 + pulse * 6, 0, Math.PI * 2);
        ctx.fill();

        // Core dot
        ctx.fillStyle = '#ff3366';
        ctx.beginPath();
        ctx.arc(pos.x, pos.y, 3, 0, Math.PI * 2);
        ctx.fill();
      });

      // Defense center
      const centerPulse = Math.sin(time * 0.004) * 0.5 + 0.5;
      const cg = ctx.createRadialGradient(center.x, center.y, 0, center.x, center.y, 16 + centerPulse * 8);
      cg.addColorStop(0, 'rgba(0, 240, 255, 0.5)');
      cg.addColorStop(1, 'rgba(0, 240, 255, 0)');
      ctx.fillStyle = cg;
      ctx.beginPath();
      ctx.arc(center.x, center.y, 16 + centerPulse * 8, 0, Math.PI * 2);
      ctx.fill();

      ctx.fillStyle = '#00f0ff';
      ctx.beginPath();
      ctx.arc(center.x, center.y, 4, 0, Math.PI * 2);
      ctx.fill();
    }

    // Create new attack line
    function spawnAttackLine() {
      const origin = ATTACK_ORIGINS[Math.floor(Math.random() * ATTACK_ORIGINS.length)];
      const pos = latLngToXY(origin.lat, origin.lng);
      attackLines.current.push({
        from: pos,
        to: center,
        progress: 0,
        speed: 0.005 + Math.random() * 0.01,
        severity: Math.random() > 0.7 ? 'critical' : 'normal',
      });
    }

    // Draw attack lines
    function drawAttackLines(time) {
      attackLines.current = attackLines.current.filter((line) => line.progress < 1.3);

      attackLines.current.forEach((line) => {
        line.progress += line.speed;
        const p = Math.min(line.progress, 1);

        // Curved path using quadratic bezier
        const midX = (line.from.x + line.to.x) / 2;
        const midY = Math.min(line.from.y, line.to.y) - 40;

        // Calculate point on curve
        const t = p;
        const x = (1 - t) * (1 - t) * line.from.x + 2 * (1 - t) * t * midX + t * t * line.to.x;
        const y = (1 - t) * (1 - t) * line.from.y + 2 * (1 - t) * t * midY + t * t * line.to.y;

        // Draw trail
        const trailLength = 0.15;
        const startT = Math.max(0, t - trailLength);

        ctx.beginPath();
        ctx.moveTo(
          (1 - startT) * (1 - startT) * line.from.x + 2 * (1 - startT) * startT * midX + startT * startT * line.to.x,
          (1 - startT) * (1 - startT) * line.from.y + 2 * (1 - startT) * startT * midY + startT * startT * line.to.y
        );

        for (let i = startT; i <= t; i += 0.02) {
          const px = (1 - i) * (1 - i) * line.from.x + 2 * (1 - i) * i * midX + i * i * line.to.x;
          const py = (1 - i) * (1 - i) * line.from.y + 2 * (1 - i) * i * midY + i * i * line.to.y;
          ctx.lineTo(px, py);
        }

        const color = line.severity === 'critical' ? '255, 51, 102' : '255, 170, 0';
        ctx.strokeStyle = `rgba(${color}, ${0.6 * (1 - p * 0.5)})`;
        ctx.lineWidth = line.severity === 'critical' ? 2 : 1;
        ctx.stroke();

        // Leading dot
        if (p < 1) {
          ctx.fillStyle = `rgba(${color}, 0.9)`;
          ctx.beginPath();
          ctx.arc(x, y, line.severity === 'critical' ? 3 : 2, 0, Math.PI * 2);
          ctx.fill();
        }

        // Impact effect
        if (p >= 1 && line.progress < 1.2) {
          const impactAlpha = 1 - (line.progress - 1) / 0.2;
          const impactRadius = (line.progress - 1) / 0.2 * 20;
          ctx.strokeStyle = `rgba(${color}, ${impactAlpha * 0.5})`;
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.arc(line.to.x, line.to.y, impactRadius, 0, Math.PI * 2);
          ctx.stroke();
        }
      });
    }

    let spawnTimer = 0;
    function animate(time) {
      ctx.clearRect(0, 0, width, height);
      drawGrid();
      drawLandDots();
      drawNodes(time);
      drawAttackLines(time);

      spawnTimer++;
      if (spawnTimer > 40) {
        spawnAttackLine();
        spawnTimer = 0;
      }

      animRef.current = requestAnimationFrame(animate);
    }

    animRef.current = requestAnimationFrame(animate);

    return () => {
      cancelAnimationFrame(animRef.current);
      window.removeEventListener('resize', resize);
    };
  }, []);

  return (
    <div className="threat-map-container">
      <canvas ref={canvasRef}></canvas>
      <div className="map-legend">
        <div className="legend-item">
          <div className="legend-dot" style={{ background: '#ff3366' }}></div>
          Attack Origin
        </div>
        <div className="legend-item">
          <div className="legend-dot" style={{ background: '#ffaa00' }}></div>
          Suspicious
        </div>
        <div className="legend-item">
          <div className="legend-dot" style={{ background: '#00f0ff' }}></div>
          Defense Center
        </div>
      </div>
    </div>
  );
}
