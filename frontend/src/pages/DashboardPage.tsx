/** Dashboard — real-time stats from backend, charts for threat/severity distribution. */

import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { dashboardApi } from '../api/client';
import type { DashboardStats } from '../types';
import {
  FolderOpen, Shield, AlertTriangle, Search, FileWarning, Flame
} from 'lucide-react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell,
} from 'recharts';

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#dc2626', high: '#f97316', medium: '#eab308', low: '#22c55e',
};
const CHART_COLORS = ['#3b82f6', '#8b5cf6', '#f97316', '#ef4444', '#10b981', '#eab308', '#ec4899'];

export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    dashboardApi.stats()
      .then((r) => setStats(r.data))
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="flex justify-center py-20"><div className="animate-spin w-8 h-8 border-2 border-cyber-accent border-t-transparent rounded-full" /></div>;

  const s = stats || {} as DashboardStats;

  const threatData = Object.entries(s.threat_distribution || {}).map(([name, value]) => ({ name, value }));
  const severityData = Object.entries(s.severity_distribution || {}).map(([name, value]) => ({ name, value }));

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Investigation Dashboard</h1>
        <p className="text-gray-500 text-sm mt-1">Real-time overview of forensic analysis</p>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        <StatCard icon={FolderOpen} label="Total Cases" value={s.total_cases} color="blue" />
        <StatCard icon={FolderOpen} label="Active Cases" value={s.active_cases} color="green" />
        <StatCard icon={Search} label="Evidence Items" value={s.total_evidence} color="purple" />
        <StatCard icon={Shield} label="Threats" value={s.total_threats} color="red" />
        <StatCard icon={AlertTriangle} label="Anomalies" value={s.total_anomalies} color="orange" />
        <StatCard icon={Flame} label="Critical" value={s.critical_incidents} color="crimson" />
      </div>

      {/* Charts */}
      <div className="grid lg:grid-cols-2 gap-6">
        {/* Threat Distribution */}
        <div className="card">
          <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-4">Threat Distribution</h3>
          {threatData.length > 0 ? (
            <ResponsiveContainer width="100%" height={280}>
              <BarChart data={threatData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
                <XAxis dataKey="name" tick={{ fontSize: 10 }} angle={-20} textAnchor="end" height={60} />
                <YAxis tick={{ fontSize: 11 }} />
                <Tooltip contentStyle={{ background: '#111827', border: '1px solid #374151', borderRadius: '8px' }} />
                <Bar dataKey="value" fill="#3b82f6" radius={[4, 4, 0, 0]}>
                  {threatData.map((_, i) => <Cell key={i} fill={CHART_COLORS[i % CHART_COLORS.length]} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : <p className="text-gray-600 text-sm py-12 text-center">No threats detected</p>}
        </div>

        {/* Severity Distribution */}
        <div className="card">
          <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-4">Severity Distribution</h3>
          {severityData.length > 0 ? (
            <ResponsiveContainer width="100%" height={280}>
              <PieChart>
                <Pie data={severityData} cx="50%" cy="50%" outerRadius={100} dataKey="value" label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}>
                  {severityData.map((entry) => <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name] || '#6b7280'} />)}
                </Pie>
                <Tooltip contentStyle={{ background: '#111827', border: '1px solid #374151', borderRadius: '8px' }} />
              </PieChart>
            </ResponsiveContainer>
          ) : <p className="text-gray-600 text-sm py-12 text-center">No severity data available</p>}
        </div>
      </div>

      {/* Top IPs */}
      <div className="grid lg:grid-cols-2 gap-6">
        <div className="card">
          <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-4">Top Source IPs</h3>
          {(s.top_source_ips || []).length > 0 ? (
            <div className="space-y-2">
              {s.top_source_ips.map((item, i) => (
                <div key={i} className="flex justify-between items-center py-2 px-3 bg-gray-800/30 rounded-lg">
                  <span className="font-mono text-sm text-gray-300">{item.ip}</span>
                  <span className="badge severity-high">{item.count}</span>
                </div>
              ))}
            </div>
          ) : <p className="text-gray-600 text-sm text-center py-6">No data available</p>}
        </div>

        <div className="card">
          <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-4">Top Destination IPs</h3>
          {(s.top_dest_ips || []).length > 0 ? (
            <div className="space-y-2">
              {s.top_dest_ips.map((item, i) => (
                <div key={i} className="flex justify-between items-center py-2 px-3 bg-gray-800/30 rounded-lg">
                  <span className="font-mono text-sm text-gray-300">{item.ip}</span>
                  <span className="badge severity-medium">{item.count}</span>
                </div>
              ))}
            </div>
          ) : <p className="text-gray-600 text-sm text-center py-6">No data available</p>}
        </div>
      </div>

      {/* Recent cases */}
      <div className="card">
        <div className="flex justify-between items-center mb-4">
          <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider">Recent Cases</h3>
          <Link to="/cases" className="text-cyber-accent text-sm hover:underline">View all →</Link>
        </div>
        {(s.recent_cases || []).length > 0 ? (
          <div className="space-y-2">
            {s.recent_cases.map((c) => (
              <Link key={c.id} to={`/cases/${c.id}`}
                className="flex items-center justify-between py-3 px-4 bg-gray-800/20 rounded-lg hover:bg-gray-800/40 transition-colors">
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

function StatCard({ icon: Icon, label, value, color }: { icon: any; label: string; value: number; color: string }) {
  const colorMap: Record<string, string> = {
    blue: 'from-blue-500/20 to-blue-600/5 border-blue-500/20 text-blue-400',
    green: 'from-emerald-500/20 to-emerald-600/5 border-emerald-500/20 text-emerald-400',
    purple: 'from-purple-500/20 to-purple-600/5 border-purple-500/20 text-purple-400',
    red: 'from-red-500/20 to-red-600/5 border-red-500/20 text-red-400',
    orange: 'from-orange-500/20 to-orange-600/5 border-orange-500/20 text-orange-400',
    crimson: 'from-red-600/20 to-red-700/5 border-red-600/20 text-red-500',
  };
  return (
    <div className={`stat-card bg-gradient-to-br ${colorMap[color]} border`}>
      <Icon className="w-5 h-5 opacity-70" />
      <p className="text-2xl font-bold text-white">{value ?? 0}</p>
      <p className="text-xs text-gray-500">{label}</p>
    </div>
  );
}
