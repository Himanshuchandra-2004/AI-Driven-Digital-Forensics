/** Audit Logs page — live API audit logs with forensic inspection and stats (Admin only). */

import { useEffect, useState, useMemo } from 'react';
import { systemApi } from '../api/client';
import { useAuth } from '../context/AuthContext';
import type { AuditLogEntry } from '../types';
import { 
  ShieldAlert, RefreshCw, Search, Filter, Activity, 
  Clock, AlertTriangle, CheckCircle2, Lock 
} from 'lucide-react';

export default function AuditLogsPage() {
  const { user } = useAuth();
  const [logs, setLogs] = useState<AuditLogEntry[]>([]);
  const [totalEntries, setTotalEntries] = useState(0);
  const [loading, setLoading] = useState(true);
  const [limit, setLimit] = useState(50);
  const [search, setSearch] = useState('');
  const [methodFilter, setMethodFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const res = await systemApi.auditLog(limit);
      setLogs(res.data.entries || []);
      setTotalEntries(res.data.total_entries || 0);
    } catch (err) {
      console.error('Failed to fetch audit logs:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (user?.role === 'admin') {
      fetchLogs();
    } else {
      setLoading(false);
    }
  }, [user, limit]);

  const filteredLogs = useMemo(() => {
    return logs.filter((entry) => {
      if (methodFilter !== 'ALL' && entry.method.toUpperCase() !== methodFilter) {
        return false;
      }
      if (statusFilter === '2xx' && (entry.status_code < 200 || entry.status_code >= 300)) {
        return false;
      }
      if (statusFilter === '4xx' && (entry.status_code < 400 || entry.status_code >= 500)) {
        return false;
      }
      if (statusFilter === '5xx' && entry.status_code < 500) {
        return false;
      }
      if (search.trim()) {
        const q = search.toLowerCase();
        const matchesPath = entry.path.toLowerCase().includes(q);
        const matchesIp = entry.client_ip.toLowerCase().includes(q);
        const matchesReqId = entry.request_id?.toLowerCase().includes(q);
        if (!matchesPath && !matchesIp && !matchesReqId) return false;
      }
      return true;
    });
  }, [logs, methodFilter, statusFilter, search]);

  const stats = useMemo(() => {
    const errorCount = logs.filter((l) => l.status_code >= 400).length;
    const avgDuration = logs.length 
      ? Math.round(logs.reduce((acc, l) => acc + (l.duration_ms || 0), 0) / logs.length * 10) / 10 
      : 0;
    return { errorCount, avgDuration };
  }, [logs]);

  if (user?.role !== 'admin') {
    return (
      <div className="card text-center py-20 space-y-4 max-w-xl mx-auto my-12">
        <div className="w-16 h-16 rounded-full bg-red-500/10 border border-red-500/30 flex items-center justify-center mx-auto text-red-400">
          <Lock className="w-8 h-8" />
        </div>
        <h2 className="text-xl font-bold text-white">Administrator Access Required</h2>
        <p className="text-gray-400 text-sm">
          System audit logs contain sensitive infrastructure activity. Only users with the <span className="text-red-400 font-semibold uppercase">ADMIN</span> role can access this page.
        </p>
        <p className="text-xs text-gray-500">
          Currently signed in as: <span className="text-white font-mono">{user?.username}</span> (Role: <span className="uppercase">{user?.role}</span>)
        </p>
      </div>
    );
  }

  const getMethodBadge = (method: string) => {
    switch (method.toUpperCase()) {
      case 'GET':
        return 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30';
      case 'POST':
        return 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30';
      case 'DELETE':
        return 'bg-red-500/15 text-red-400 border-red-500/30';
      case 'PUT':
      case 'PATCH':
        return 'bg-amber-500/15 text-amber-400 border-amber-500/30';
      default:
        return 'bg-gray-500/15 text-gray-400 border-gray-500/30';
    }
  };

  const getStatusBadge = (status: number) => {
    if (status >= 200 && status < 300) {
      return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
    }
    if (status >= 400 && status < 500) {
      return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
    }
    if (status >= 500) {
      return 'bg-red-500/10 text-red-400 border-red-500/30';
    }
    return 'bg-blue-500/10 text-blue-400 border-blue-500/30';
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="page-title">System Audit Log</h1>
            <span className="badge bg-red-500/20 text-red-400 border-red-500/40 uppercase text-xs font-semibold">
              Admin Only
            </span>
          </div>
          <p className="text-gray-500 text-sm mt-1">
            Real-time HTTP request trace, client IP tracking, and API performance monitoring
          </p>
        </div>

        <div className="flex items-center gap-3">
          <select
            value={limit}
            onChange={(e) => setLimit(Number(e.target.value))}
            className="input-field py-1.5 px-3 text-sm bg-cyber-dark/80"
          >
            <option value={25}>Latest 25</option>
            <option value={50}>Latest 50</option>
            <option value={100}>Latest 100</option>
            <option value={200}>Latest 200</option>
          </select>

          <button
            onClick={fetchLogs}
            disabled={loading}
            className="btn-secondary flex items-center gap-2 text-sm py-1.5 px-3"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* KPI Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="card flex items-center gap-4">
          <div className="p-3 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
            <Activity className="w-5 h-5" />
          </div>
          <div>
            <p className="text-xs text-gray-500 uppercase tracking-wider">Entries In Memory</p>
            <p className="text-xl font-bold text-white">{totalEntries}</p>
          </div>
        </div>

        <div className="card flex items-center gap-4">
          <div className="p-3 rounded-lg bg-amber-500/10 text-amber-400 border border-amber-500/20">
            <AlertTriangle className="w-5 h-5" />
          </div>
          <div>
            <p className="text-xs text-gray-500 uppercase tracking-wider">Client / Server Errors</p>
            <p className="text-xl font-bold text-amber-400">{stats.errorCount}</p>
          </div>
        </div>

        <div className="card flex items-center gap-4">
          <div className="p-3 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <Clock className="w-5 h-5" />
          </div>
          <div>
            <p className="text-xs text-gray-500 uppercase tracking-wider">Avg Latency</p>
            <p className="text-xl font-bold text-emerald-400">{stats.avgDuration} ms</p>
          </div>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="card p-4 flex flex-col md:flex-row gap-3 items-stretch md:items-center justify-between">
        <div className="relative flex-1">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Filter by endpoint path, client IP, or request ID..."
            className="input-field w-full pl-9 py-1.5 text-sm"
          />
        </div>

        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-gray-500" />
          <select
            value={methodFilter}
            onChange={(e) => setMethodFilter(e.target.value)}
            className="input-field py-1.5 px-3 text-xs bg-cyber-dark/80"
          >
            <option value="ALL">All Methods</option>
            <option value="GET">GET</option>
            <option value="POST">POST</option>
            <option value="PUT">PUT</option>
            <option value="DELETE">DELETE</option>
          </select>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="input-field py-1.5 px-3 text-xs bg-cyber-dark/80"
          >
            <option value="ALL">All Status</option>
            <option value="2xx">2xx Success</option>
            <option value="4xx">4xx Client Errors</option>
            <option value="5xx">5xx Server Errors</option>
          </select>
        </div>
      </div>

      {/* Logs Table */}
      {loading && logs.length === 0 ? (
        <div className="flex justify-center py-20">
          <div className="animate-spin w-8 h-8 border-2 border-cyber-accent border-t-transparent rounded-full" />
        </div>
      ) : filteredLogs.length === 0 ? (
        <div className="card text-center py-16">
          <CheckCircle2 className="w-12 h-12 text-gray-700 mx-auto mb-4" />
          <p className="text-gray-400">No audit log entries matching current filters.</p>
        </div>
      ) : (
        <div className="card overflow-x-auto p-0">
          <table className="w-full text-left text-sm text-gray-300">
            <thead className="bg-cyber-dark/80 text-[11px] uppercase tracking-wider text-gray-500 border-b border-cyber-border">
              <tr>
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4">Method</th>
                <th className="py-3 px-4">Endpoint Path</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Duration</th>
                <th className="py-3 px-4">Client IP</th>
                <th className="py-3 px-4">Request ID</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-cyber-border/40 font-mono text-xs">
              {filteredLogs.map((entry, idx) => (
                <tr key={idx} className="hover:bg-white/[0.02] transition-colors">
                  <td className="py-3 px-4 whitespace-nowrap text-gray-400 font-sans text-xs">
                    {new Date(entry.timestamp).toLocaleTimeString()}
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap">
                    <span className={`inline-block px-2 py-0.5 rounded text-[10px] font-bold border ${getMethodBadge(entry.method)}`}>
                      {entry.method}
                    </span>
                  </td>
                  <td className="py-3 px-4 font-semibold text-gray-200">
                    {entry.path}
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap">
                    <span className={`inline-block px-2 py-0.5 rounded text-[11px] font-semibold border ${getStatusBadge(entry.status_code)}`}>
                      {entry.status_code}
                    </span>
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap">
                    <span className={entry.duration_ms > 200 ? 'text-amber-400' : 'text-gray-400'}>
                      {entry.duration_ms} ms
                    </span>
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap text-gray-400">
                    {entry.client_ip}
                  </td>
                  <td className="py-3 px-4 whitespace-nowrap text-gray-600 text-[11px] truncate max-w-[120px]" title={entry.request_id}>
                    {entry.request_id ? entry.request_id.slice(0, 12) + '...' : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
