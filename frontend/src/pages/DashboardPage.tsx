/** Dashboard — live stats with glowing gradient charts over a moving neon network. */

import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { dashboardApi } from '../api/client';
import type { DashboardStats } from '../types';
import { FolderOpen, Shield, AlertTriangle, Search, Flame } from 'lucide-react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell,
} from 'recharts';

const SEVERITY_COLORS: Record<string, string> = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' };
const CHART_COLORS = ['#22d3ee', '#3b82f6', '#6366f1', '#14b8a6', '#0ea5e9', '#8b5cf6', '#64748b'];
const TIP = { background: 'rgba(4,8,16,.96)', border: '1px solid rgba(34,211,238,.5)', borderRadius: '10px', color: '#e6f0ff' };

function CountUp({ value }: { value: number }) {
  const [n, setN] = useState(0);
  useEffect(() => {
    const end = value ?? 0;
    const t0 = performance.now();
    let raf = 0;
    const tick = (t: number) => {
      const p = Math.min(1, (t - t0) / 900);
      setN(Math.round(end * (1 - Math.pow(1 - p, 3))));
      if (p < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [value]);
  return <>{n}</>;
}

export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    dashboardApi.stats().then((r) => setStats(r.data)).catch(console.error).finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="flex justify-center py-20"><div className="animate-spin w-8 h-8 border-2 border-cyber-accent border-t-transparent rounded-full" /></div>;

  const s = stats || ({} as DashboardStats);
  const threatData = Object.entries(s.threat_distribution || {}).map(([name, value]) => ({ name, value: Number(value) }));
  const severityData = Object.entries(s.severity_distribution || {}).map(([name, value]) => ({ name, value: Number(value) }));
  const sevTotal = severityData.reduce((a, b) => a + b.value, 0);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="page-title">Investigation Dashboard</h1>
        <p className="text-gray-500 text-sm mt-1">Real-time overview of forensic analysis</p>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        <StatCard icon={FolderOpen} label="Total Cases" value={s.total_cases} color="blue" />
        <StatCard icon={FolderOpen} label="Active Cases" value={s.active_cases} color="green" />
        <StatCard icon={Search} label="Evidence Items" value={s.total_evidence} color="purple" />
        <StatCard icon={Shield} label="Threats" value={s.total_threats} color="red" />
        <StatCard icon={AlertTriangle} label="Anomalies" value={s.total_anomalies} color="orange" />
        <StatCard icon={Flame} label="Critical" value={s.critical_incidents} color="crimson" />
      </div>

      <div className="grid lg:grid-cols-2 gap-6">
        <div className="card">
          <h3 className="card-title">Threat Distribution</h3>
          {threatData.length > 0 ? (
            <ResponsiveContainer width="100%" height={290}>
              <BarChart data={threatData}>
                <defs>
                  {CHART_COLORS.map((c, i) => (
                    <linearGradient key={c} id={`tg${i}`} x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0" stopColor={c} stopOpacity={1} /><stop offset="1" stopColor={c} stopOpacity={0.15} />
                    </linearGradient>
                  ))}
                </defs>
                <CartesianGrid strokeDasharray="3 6" vertical={false} />
                <XAxis dataKey="name" tick={{ fontSize: 10 }} angle={-20} textAnchor="end" height={60} />
                <YAxis tick={{ fontSize: 11 }} />
                <Tooltip contentStyle={TIP} cursor={{ fill: 'rgba(0,200,255,.08)' }} />
                <Bar dataKey="value" radius={[10, 10, 0, 0]} animationDuration={1400} className="glow-svg">
                  {threatData.map((_, i) => <Cell key={i} fill={`url(#tg${i % CHART_COLORS.length})`} stroke={CHART_COLORS[i % CHART_COLORS.length]} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : <p className="text-gray-600 text-sm py-12 text-center">No threats detected</p>}
        </div>

        <div className="card">
          <h3 className="card-title">Severity Distribution</h3>
          {severityData.length > 0 ? (
            <>
              <div className="relative">
                <ResponsiveContainer width="100%" height={250}>
                  <PieChart>
                    <Pie data={severityData} dataKey="value" nameKey="name" innerRadius={68} outerRadius={105} paddingAngle={4} cornerRadius={8} stroke="none" animationDuration={1400} className="glow-svg">
                      {severityData.map((e) => <Cell key={e.name} fill={SEVERITY_COLORS[e.name] || '#6b7280'} />)}
                    </Pie>
                    <Tooltip contentStyle={TIP} />
                  </PieChart>
                </ResponsiveContainer>
                <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                  <span className="text-3xl font-bold text-white">{sevTotal}</span>
                  <span className="text-[11px] uppercase tracking-widest text-gray-500">Findings</span>
                </div>
              </div>
              <div className="flex flex-wrap justify-center gap-4 text-xs text-gray-400">
                {severityData.map((e) => (
                  <span key={e.name} className="flex items-center gap-1.5 capitalize">
                    <i className="w-2.5 h-2.5 rounded-full inline-block" style={{ background: SEVERITY_COLORS[e.name] || '#6b7280' }} />{e.name} · {e.value}
                  </span>
                ))}
              </div>
            </>
          ) : <p className="text-gray-600 text-sm py-12 text-center">No severity data available</p>}
        </div>
      </div>

      <div className="grid lg:grid-cols-2 gap-6">
        <IpList title="Top Source IPs" items={s.top_source_ips} color="#f97316" />
        <IpList title="Top Destination IPs" items={s.top_dest_ips} color="#00c8ff" />
      </div>

      <div className="card">
        <div className="flex justify-between items-center mb-4">
          <h3 className="card-title !mb-0">Recent Cases</h3>
          <Link to="/cases" className="text-cyber-accent text-sm hover:underline">View all →</Link>
        </div>
        {(s.recent_cases || []).length > 0 ? (
          <div className="space-y-2">
            {s.recent_cases.map((c) => (
              <Link key={c.id} to={`/cases/${c.id}`}
                className="flex items-center justify-between py-3 px-4 bg-gray-800/20 rounded-lg hover:bg-gray-800/40 hover:translate-x-1 transition-all">
                <div>
                  <p className="text-sm font-medium text-white">{c.name}</p>
                  <p className="text-xs text-gray-500">{new Date(c.created_at).toLocaleDateString()}</p>
                </div>
                <div className="flex items-center gap-3">
                  {c.severity && <span className={`badge severity-${c.severity}`}>{c.severity}</span>}
                  <span className="text-xs text-gray-500">{c.status}</span>
                </div>
              </Link>
            ))}
          </div>
        ) : <p className="text-gray-600 text-sm text-center py-6">No cases yet. Create one or load a demo.</p>}
      </div>
    </div>
  );
}

function IpList({ title, items, color }: { title: string; items?: { ip: string; count: number }[]; color: string }) {
  const max = Math.max(1, ...(items || []).map((i) => i.count));
  return (
    <div className="card">
      <h3 className="card-title">{title}</h3>
      {(items || []).length > 0 ? (
        <div className="space-y-3">
          {items!.map((item, i) => (
            <div key={i}>
              <div className="flex justify-between text-sm mb-1">
                <span className="font-mono text-gray-300">{item.ip}</span>
                <span className="font-semibold" style={{ color }}>{item.count}</span>
              </div>
              <div className="h-1.5 rounded-full bg-gray-800/50 overflow-hidden">
                <div className="h-full rounded-full bar-grow" style={{ width: `${(item.count / max) * 100}%`, background: `linear-gradient(90deg, ${color}, #4a5bff)`, boxShadow: `0 0 10px ${color}` }} />
              </div>
            </div>
          ))}
        </div>
      ) : <p className="text-gray-600 text-sm text-center py-6">No data available</p>}
    </div>
  );
}

function StatCard({ icon: Icon, label, value, color }: { icon: any; label: string; value: number; color: string }) {
  const colorMap: Record<string, string> = {
    blue: 'from-blue-500/20 to-blue-600/5 border-blue-500/30 text-blue-400',
    green: 'from-emerald-500/20 to-emerald-600/5 border-emerald-500/30 text-emerald-400',
    purple: 'from-purple-500/20 to-purple-600/5 border-purple-500/30 text-purple-400',
    red: 'from-red-500/20 to-red-600/5 border-red-500/30 text-red-400',
    orange: 'from-orange-500/20 to-orange-600/5 border-orange-500/30 text-orange-400',
    crimson: 'from-red-600/20 to-red-700/5 border-red-600/30 text-red-500',
  };
  return (
    <div className={`stat-card stat-hover bg-gradient-to-br ${colorMap[color]} border`}>
      <Icon className="w-5 h-5 opacity-80" />
      <p className="text-2xl font-bold text-white"><CountUp value={value} /></p>
      <p className="text-xs text-gray-500">{label}</p>
    </div>
  );
}
