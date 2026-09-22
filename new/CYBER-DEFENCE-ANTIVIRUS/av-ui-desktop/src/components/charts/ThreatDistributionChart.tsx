import { useEffect, useMemo, useRef } from 'react';

type ThreatBucket = {
  name: string;
  count: number;
};

type Severity = 'critical' | 'high' | 'medium' | 'low';

const SEVERITY_GRADIENTS: Record<
  Severity,
  { top: string; mid: string; bottom: string; glow: string; label: string; dot: string; legend: string }
> = {
  critical: {
    top: '#ff3366',
    mid: '#e6194b',
    bottom: '#8b0032',
    glow: 'rgba(255,51,102,0.5)',
    label: '#ff6688',
    dot: '#ff3366',
    legend: 'Critical',
  },
  high: {
    top: '#ff6b35',
    mid: '#f25c19',
    bottom: '#993d14',
    glow: 'rgba(255,107,53,0.45)',
    label: '#ff8855',
    dot: '#ff6b35',
    legend: 'High',
  },
  medium: {
    top: '#ffaa00',
    mid: '#e69500',
    bottom: '#805300',
    glow: 'rgba(255,170,0,0.40)',
    label: '#ffcc44',
    dot: '#ffaa00',
    legend: 'Medium',
  },
  low: {
    top: '#00d4ff',
    mid: '#00a8cc',
    bottom: '#005577',
    glow: 'rgba(0,212,255,0.35)',
    label: '#44ddff',
    dot: '#00d4ff',
    legend: 'Low',
  },
};

function classifyThreatSeverity(name: string): Severity {
  const n = name.toLowerCase();
  if (
    n.includes('ransom') ||
    n.includes('rootkit') ||
    n.includes('backdoor') ||
    n.includes('trojan') ||
    n.includes(' rat') ||
    n.includes('c2') ||
    n.includes('highrisk') ||
    n.includes('ml.high')
  ) {
    return 'critical';
  }
  if (
    n.includes('eicar') ||
    n.includes('worm') ||
    n.includes('spyware') ||
    n.includes('keylog') ||
    n.includes('ml.') ||
    n.includes('embedded') ||
    n.includes('packed')
  ) {
    return 'high';
  }
  if (n.includes('adware') || n.includes('pup') || n.includes('suspicious') || n.includes('riskware')) {
    return 'medium';
  }
  return 'low';
}

type Props = {
  data: ThreatBucket[];
};

export default function ThreatDistributionChart({ data }: Props) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const presentSeverities = useMemo(() => {
    const set = new Set<Severity>();
    for (const item of data) set.add(classifyThreatSeverity(item.name));
    return Array.from(set);
  }, [data]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const dpr = window.devicePixelRatio || 1;
    const width = canvas.clientWidth;
    const height = canvas.clientHeight;
    canvas.width = Math.floor(width * dpr);
    canvas.height = Math.floor(height * dpr);
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, width, height);

    const left = 34;
    const top = 18;
    const chartWidth = width - left - 14;
    const chartHeight = height - top - 78;
    const maxCount = Math.max(...data.map((d) => d.count), 1);

    for (let i = 0; i <= 4; i++) {
      const y = top + (chartHeight / 4) * i;
      ctx.strokeStyle = 'rgba(0, 212, 255, 0.08)';
      ctx.lineWidth = 1;
      ctx.setLineDash([4, 4]);
      ctx.beginPath();
      ctx.moveTo(left, y);
      ctx.lineTo(left + chartWidth, y);
      ctx.stroke();
      ctx.setLineDash([]);

      const val = Math.round(maxCount * (1 - i / 4));
      ctx.fillStyle = 'rgba(255,255,255,0.30)';
      ctx.font = '10px "JetBrains Mono", monospace';
      ctx.textAlign = 'right';
      ctx.fillText(val.toLocaleString(), left - 8, y + 4);
    }

    if (data.length === 0) return;
    const minVisibleHeight = 32;
    const barWidth = Math.min(70, (chartWidth / data.length) * 0.6);
    const spacing = chartWidth / data.length;

    data.forEach((item, i) => {
      if (item.count === 0) return;
      const severity = classifyThreatSeverity(item.name);
      const colors = SEVERITY_GRADIENTS[severity];
      const rawBarHeight = (item.count / maxCount) * chartHeight;
      const barH = Math.max(rawBarHeight, minVisibleHeight);
      const x = left + spacing * i + (spacing - barWidth) / 2;
      const y = top + chartHeight - barH;
      const r = 6;

      ctx.shadowColor = colors.glow;
      ctx.shadowBlur = 18;
      const grad = ctx.createLinearGradient(x, y, x, y + barH);
      grad.addColorStop(0, colors.top);
      grad.addColorStop(0.5, colors.mid);
      grad.addColorStop(1, colors.bottom);

      ctx.beginPath();
      ctx.moveTo(x + r, y);
      ctx.lineTo(x + barWidth - r, y);
      ctx.quadraticCurveTo(x + barWidth, y, x + barWidth, y + r);
      ctx.lineTo(x + barWidth, y + barH);
      ctx.lineTo(x, y + barH);
      ctx.lineTo(x, y + r);
      ctx.quadraticCurveTo(x, y, x + r, y);
      ctx.closePath();
      ctx.fillStyle = grad;
      ctx.fill();
      ctx.shadowBlur = 0;

      ctx.fillStyle = 'rgba(255,255,255,0.25)';
      ctx.fillRect(x + 2, y, Math.max(0, barWidth - 4), 1.5);

      ctx.fillStyle = colors.label;
      ctx.font = 'bold 16px "JetBrains Mono", monospace';
      ctx.textAlign = 'center';
      ctx.shadowColor = colors.glow;
      ctx.shadowBlur = 8;
      ctx.fillText(item.count.toLocaleString(), x + barWidth / 2, y - 10);
      ctx.shadowBlur = 0;

      const nameStr = item.name.length > 13 ? `${item.name.slice(0, 12)}…` : item.name;
      ctx.fillStyle = 'rgba(255,255,255,0.60)';
      ctx.font = '11px "JetBrains Mono", monospace';
      ctx.textAlign = 'center';
      ctx.fillText(nameStr, x + barWidth / 2, top + chartHeight + 18);

      ctx.beginPath();
      ctx.arc(x + barWidth / 2, top + chartHeight + 32, 4, 0, Math.PI * 2);
      ctx.fillStyle = colors.dot;
      ctx.shadowColor = colors.glow;
      ctx.shadowBlur = 6;
      ctx.fill();
      ctx.shadowBlur = 0;
    });
  }, [data]);

  return (
    <div className="threat-distribution-wrap">
      <div className="threat-severity-legend">
        {presentSeverities.map((severity) => {
          const c = SEVERITY_GRADIENTS[severity];
          return (
            <span key={severity} style={{ color: c.label }}>
              <i style={{ background: c.dot, boxShadow: `0 0 8px ${c.glow}` }} />
              {c.legend}
            </span>
          );
        })}
      </div>
      <canvas ref={canvasRef} className="threat-distribution-canvas" />
    </div>
  );
}
