/** Case Detail — tabbed view with all forensic analysis views. */

import { useEffect, useState, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  casesApi, analysisApi, threatsApi, anomaliesApi,
  evidenceApi, incidentsApi, reportsApi,
} from '../api/client';
import type {
  Case, AnalysisRun, ThreatDetection, AnomalyDetection,
  Evidence, Incident, ChainOfCustodyEntry, EvidenceVerification, ReportInfo,
} from '../types';
import {
  Upload, Play, FileText, Shield, AlertTriangle, Link2,
  CheckCircle, XCircle, Download, Clock, Info, Trash2,
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Cell,
} from 'recharts';

const TABS = ['Overview', 'Evidence', 'Threats', 'Anomalies', 'Incidents', 'Correlation', 'Chain of Custody', 'Reports'];
const CHART_COLORS = ['#3b82f6', '#8b5cf6', '#f97316', '#ef4444', '#10b981', '#eab308', '#ec4899'];

export default function CaseDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { user } = useAuth();
  const [tab, setTab] = useState('Overview');
  const [caseData, setCaseData] = useState<Case | null>(null);
  const [runs, setRuns] = useState<AnalysisRun[]>([]);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [threats, setThreats] = useState<ThreatDetection[]>([]);
  const [anomalies, setAnomalies] = useState<AnomalyDetection[]>([]);
  const [evidence, setEvidence] = useState<Evidence[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [uploadedFilename, setUploadedFilename] = useState('');

  const load = useCallback(async () => {
    if (!id) return;
    try {
      const [c, r] = await Promise.all([
        casesApi.get(id),
        analysisApi.list(id),
      ]);
      setCaseData(c.data);
      setRuns(r.data);

      // Load analysis results if completed
      if (c.data.status === 'completed' || c.data.evidence_count > 0) {
        const [t, a, e, i] = await Promise.all([
          threatsApi.list(id).catch(() => ({ data: [] })),
          anomaliesApi.list(id).catch(() => ({ data: [] })),
          evidenceApi.list(id).catch(() => ({ data: [] })),
          incidentsApi.list(id).catch(() => ({ data: [] })),
        ]);
        setThreats(t.data);
        setAnomalies(a.data);
        setEvidence(e.data);
        setIncidents(i.data);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => { load(); }, [load]);

  // Auto-refresh when analyzing
  useEffect(() => {
    if (caseData?.status === 'analyzing') {
      const timer = setInterval(load, 5000);
      return () => clearInterval(timer);
    }
  }, [caseData?.status, load]);

  const handleUpload = async () => {
    if (!uploadFile || !id) return;
    setUploading(true);
    try {
      const res = await casesApi.upload(id, uploadFile);
      setUploadedFilename(res.data.internal_name);
      setUploadFile(null);
    } catch (err) {
      console.error(err);
    } finally {
      setUploading(false);
    }
  };

  const handleAnalyze = async () => {
    if (!id || !uploadedFilename) return;
    setAnalyzing(true);
    try {
      await analysisApi.start(id, uploadedFilename);
      load();
    } catch (err) {
      console.error(err);
    } finally {
      setAnalyzing(false);
    }
  };

  const handleDeleteCase = async () => {
    if (!id) return;
    setDeleting(true);
    try {
      await casesApi.delete(id);
      navigate('/cases');
    } catch (err) {
      console.error('Failed to delete case:', err);
    } finally {
      setDeleting(false);
    }
  };

  if (loading) return <div className="flex justify-center py-20"><div className="animate-spin w-8 h-8 border-2 border-cyber-accent border-t-transparent rounded-full" /></div>;
  if (!caseData) return <p className="text-gray-500">Case not found</p>;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">{caseData.name}</h1>
          <p className="text-gray-500 text-sm mt-1">{caseData.description || 'No description'}</p>
          <div className="flex items-center gap-3 mt-2">
            <span className={`badge severity-${caseData.severity || 'low'}`}>{caseData.severity || 'pending'}</span>
            <span className="text-xs text-gray-500">Status: {caseData.status}</span>
            {caseData.status === 'analyzing' && <span className="pulse-dot bg-amber-500" />}
          </div>
        </div>

        {user?.role === 'admin' && (
          <button
            onClick={() => setShowDeleteModal(true)}
            className="px-3 py-1.5 rounded-lg bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/30 text-xs font-medium flex items-center gap-1.5 transition-colors"
            title="Delete Case (Admin Only)"
          >
            <Trash2 className="w-3.5 h-3.5" />
            Delete Case
          </button>
        )}
      </div>

      {/* Delete Confirmation Modal (Admin Only) */}
      {showDeleteModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4" onClick={() => setShowDeleteModal(false)}>
          <div onClick={(e) => e.stopPropagation()} className="card w-full max-w-md space-y-4 border-red-500/40 shadow-2xl shadow-red-950/50">
            <div className="flex items-center gap-3 text-red-400">
              <div className="p-2 rounded-lg bg-red-500/10 border border-red-500/20">
                <AlertTriangle className="w-6 h-6" />
              </div>
              <h2 className="text-lg font-bold text-white">Delete Case Permanently?</h2>
            </div>
            <p className="text-sm text-gray-300">
              Are you sure you want to delete <span className="text-white font-semibold">"{caseData.name}"</span>?
            </p>
            <p className="text-xs text-gray-400 bg-red-500/10 p-3 rounded border border-red-500/20">
              ⚠️ This action cannot be undone. All associated network evidence records, machine learning threat classifications, anomaly detections, and generated reports will be permanently deleted.
            </p>
            <div className="flex justify-end gap-3 pt-2">
              <button type="button" onClick={() => setShowDeleteModal(false)} className="btn-secondary text-sm">
                Cancel
              </button>
              <button
                type="button"
                onClick={handleDeleteCase}
                disabled={deleting}
                className="px-4 py-2 rounded-lg bg-red-500/20 hover:bg-red-500/30 text-red-300 border border-red-500/40 text-sm font-medium transition-colors"
              >
                {deleting ? 'Deleting...' : 'Confirm Delete'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-1 overflow-x-auto border-b border-cyber-border pb-0">
        {TABS.map((t) => (
          <button key={t} onClick={() => setTab(t)}
            className={`px-4 py-2.5 text-sm font-medium whitespace-nowrap border-b-2 transition-colors ${tab === t ? 'border-cyber-accent text-white' : 'border-transparent text-gray-500 hover:text-gray-300'}`}>
            {t}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <div className="animate-fade-in">
        {tab === 'Overview' && <OverviewTab caseData={caseData} runs={runs} threats={threats} anomalies={anomalies} evidence={evidence} incidents={incidents}
          uploadFile={uploadFile} setUploadFile={setUploadFile} uploading={uploading} handleUpload={handleUpload}
          uploadedFilename={uploadedFilename} analyzing={analyzing} handleAnalyze={handleAnalyze} />}
        {tab === 'Evidence' && <EvidenceTab evidence={evidence} />}
        {tab === 'Threats' && <ThreatsTab threats={threats} />}
        {tab === 'Anomalies' && <AnomaliesTab anomalies={anomalies} />}
        {tab === 'Incidents' && <IncidentsTab incidents={incidents} />}
        {tab === 'Correlation' && <CorrelationTab incidents={incidents} evidence={evidence} />}
        {tab === 'Chain of Custody' && <CustodyTab evidence={evidence} />}
        {tab === 'Reports' && <ReportsTab caseId={id!} />}
      </div>
    </div>
  );
}

/* ---- Overview Tab ---- */
function OverviewTab({ caseData, runs, threats, anomalies, evidence, incidents,
  uploadFile, setUploadFile, uploading, handleUpload, uploadedFilename, analyzing, handleAnalyze }: any) {
  const threatDist = threats.reduce((acc: any, t: ThreatDetection) => {
    acc[t.predicted_class] = (acc[t.predicted_class] || 0) + 1; return acc;
  }, {});
  const chartData = Object.entries(threatDist).map(([name, value]) => ({ name, value }));

  return (
    <div className="space-y-6">
      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="stat-card"><p className="text-2xl font-bold text-white">{evidence.length}</p><p className="text-xs text-gray-500">Evidence Items</p></div>
        <div className="stat-card"><p className="text-2xl font-bold text-red-400">{threats.length}</p><p className="text-xs text-gray-500">Threats</p></div>
        <div className="stat-card"><p className="text-2xl font-bold text-orange-400">{anomalies.length}</p><p className="text-xs text-gray-500">Anomalies</p></div>
        <div className="stat-card"><p className="text-2xl font-bold text-purple-400">{incidents.length}</p><p className="text-xs text-gray-500">Incidents</p></div>
      </div>

      {/* Upload + Analyze */}
      <div className="card">
        <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-4">Data Upload & Analysis</h3>
        <div className="flex flex-wrap items-center gap-4">
          <label className="btn-secondary flex items-center gap-2 cursor-pointer">
            <Upload className="w-4 h-4" />
            <span>{uploadFile ? uploadFile.name : 'Select File'}</span>
            <input type="file" className="hidden" accept=".csv,.pcap,.log,.txt"
              onChange={(e) => setUploadFile(e.target.files?.[0] || null)} />
          </label>
          {uploadFile && (
            <button onClick={handleUpload} disabled={uploading} className="btn-primary flex items-center gap-2">
              {uploading ? 'Uploading...' : 'Upload'}
            </button>
          )}
          {uploadedFilename && (
            <button onClick={handleAnalyze} disabled={analyzing} className="btn-success flex items-center gap-2">
              <Play className="w-4 h-4" />
              {analyzing ? 'Starting...' : 'Run Analysis'}
            </button>
          )}
        </div>
        {caseData.status === 'analyzing' && (
          <div className="mt-4 flex items-center gap-2 text-amber-400 text-sm">
            <div className="animate-spin w-4 h-4 border-2 border-amber-400 border-t-transparent rounded-full" />
            Analysis in progress... This page will auto-refresh.
          </div>
        )}
      </div>

      {/* Analysis Runs */}
      {runs.length > 0 && (
        <div className="card">
          <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-4">Analysis History</h3>
          <div className="space-y-2">
            {runs.map((r: AnalysisRun) => (
              <div key={r.id} className="flex items-center justify-between py-3 px-4 bg-gray-800/30 rounded-lg">
                <div className="flex items-center gap-3">
                  <span className={`pulse-dot ${r.status === 'completed' ? 'bg-green-500' : r.status === 'processing' ? 'bg-amber-500' : r.status === 'failed' ? 'bg-red-500' : 'bg-gray-500'}`} />
                  <div>
                    <p className="text-sm text-white">{r.source_file || 'Unknown file'}</p>
                    <p className="text-xs text-gray-500">{r.total_records} records • {r.suspicious_records} suspicious</p>
                  </div>
                </div>
                <div className="text-right">
                  <p className="text-xs text-gray-500 uppercase">{r.status}</p>
                  {r.total_time && <p className="text-xs text-gray-600">{r.total_time.toFixed(1)}s</p>}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Threat chart */}
      {chartData.length > 0 && (
        <div className="card">
          <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-4">Threat Classification</h3>
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
              <XAxis dataKey="name" tick={{ fontSize: 10 }} angle={-15} textAnchor="end" height={50} />
              <YAxis tick={{ fontSize: 11 }} />
              <Tooltip contentStyle={{ background: '#111827', border: '1px solid #374151', borderRadius: '8px' }} />
              <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                {chartData.map((_: any, i: number) => <Cell key={i} fill={CHART_COLORS[i % CHART_COLORS.length]} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
}

/* ---- Evidence Tab ---- */
function EvidenceTab({ evidence }: { evidence: Evidence[] }) {
  const [verifyResult, setVerifyResult] = useState<EvidenceVerification | null>(null);
  const [verifying, setVerifying] = useState('');
  const [filter, setFilter] = useState('');

  const handleVerify = async (evId: string) => {
    setVerifying(evId);
    try {
      const res = await evidenceApi.verify(evId);
      setVerifyResult(res.data);
    } catch (err) { console.error(err); }
    finally { setVerifying(''); }
  };

  const filtered = evidence.filter((e) => {
    if (!filter) return true;
    return (e.predicted_threat?.toLowerCase().includes(filter.toLowerCase()) ||
      e.src_ip?.includes(filter) || e.dst_ip?.includes(filter) ||
      e.severity?.includes(filter));
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-4">
        <input value={filter} onChange={(e) => setFilter(e.target.value)}
          className="input-field flex-1" placeholder="Filter by IP, threat, severity..." />
        <p className="text-sm text-gray-500">{filtered.length} items</p>
      </div>

      {verifyResult && (
        <div className={`p-4 rounded-lg border ${verifyResult.integrity_verified ? 'bg-green-500/10 border-green-500/30' : 'bg-red-500/10 border-red-500/30'}`}>
          <div className="flex items-center gap-2 mb-2">
            {verifyResult.integrity_verified ? <CheckCircle className="w-5 h-5 text-green-400" /> : <XCircle className="w-5 h-5 text-red-400" />}
            <span className={`font-semibold ${verifyResult.integrity_verified ? 'text-green-400' : 'text-red-400'}`}>
              {verifyResult.message}
            </span>
          </div>
          <p className="text-xs text-gray-500 font-mono">Stored:     {verifyResult.stored_hash}</p>
          <p className="text-xs text-gray-500 font-mono">Calculated: {verifyResult.calculated_hash}</p>
        </div>
      )}

      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead><tr className="table-header">
            <th className="px-4 py-3 text-left">Type</th><th className="px-4 py-3 text-left">Threat</th>
            <th className="px-4 py-3 text-left">Severity</th><th className="px-4 py-3 text-left">Source</th>
            <th className="px-4 py-3 text-left">Destination</th><th className="px-4 py-3 text-left">Risk</th>
            <th className="px-4 py-3 text-left">Hash</th><th className="px-4 py-3 text-left">Actions</th>
          </tr></thead>
          <tbody>
            {filtered.map((e) => (
              <tr key={e.id} className="table-row">
                <td className="px-4 py-3"><span className="badge bg-gray-700 border-gray-600">{e.evidence_type}</span></td>
                <td className="px-4 py-3 text-white">{e.predicted_threat || '—'}</td>
                <td className="px-4 py-3"><span className={`badge severity-${e.severity || 'low'}`}>{e.severity || 'N/A'}</span></td>
                <td className="px-4 py-3 font-mono text-xs text-gray-400">{e.src_ip || '—'}:{e.src_port || ''}</td>
                <td className="px-4 py-3 font-mono text-xs text-gray-400">{e.dst_ip || '—'}:{e.dst_port || ''}</td>
                <td className="px-4 py-3 text-gray-300">{e.risk_score?.toFixed(1) || '—'}</td>
                <td className="px-4 py-3 font-mono text-[10px] text-gray-600 max-w-[120px] truncate" title={e.evidence_hash || ''}>{e.evidence_hash?.slice(0, 16) || '—'}...</td>
                <td className="px-4 py-3">
                  <button onClick={() => handleVerify(e.id)} disabled={verifying === e.id}
                    className="text-xs text-cyber-accent hover:underline">
                    {verifying === e.id ? 'Checking...' : 'Verify'}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {filtered.length === 0 && <p className="text-gray-600 text-sm text-center py-8">No evidence available</p>}
    </div>
  );
}

/* ---- Threats Tab ---- */
function ThreatsTab({ threats }: { threats: ThreatDetection[] }) {
  return (
    <div className="space-y-4">
      <p className="text-sm text-gray-500">{threats.length} threat detections (non-benign)</p>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead><tr className="table-header">
            <th className="px-4 py-3 text-left">Class</th><th className="px-4 py-3 text-left">Confidence</th>
            <th className="px-4 py-3 text-left">Severity</th><th className="px-4 py-3 text-left">Source</th>
            <th className="px-4 py-3 text-left">Destination</th><th className="px-4 py-3 text-left">Detected</th>
          </tr></thead>
          <tbody>
            {threats.map((t) => (
              <tr key={t.id} className="table-row">
                <td className="px-4 py-3 font-semibold text-white">{t.predicted_class}</td>
                <td className="px-4 py-3">{t.confidence ? `${(t.confidence * 100).toFixed(1)}%` : '—'}</td>
                <td className="px-4 py-3"><span className={`badge severity-${t.severity || 'low'}`}>{t.severity || 'N/A'}</span></td>
                <td className="px-4 py-3 font-mono text-xs text-gray-400">{t.src_ip || '—'}</td>
                <td className="px-4 py-3 font-mono text-xs text-gray-400">{t.dst_ip || '—'}</td>
                <td className="px-4 py-3 text-xs text-gray-500">{new Date(t.detected_at).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {threats.length === 0 && <p className="text-gray-600 text-sm text-center py-8">No threats detected</p>}
    </div>
  );
}

/* ---- Anomalies Tab ---- */
function AnomaliesTab({ anomalies }: { anomalies: AnomalyDetection[] }) {
  return (
    <div className="space-y-4">
      <p className="text-sm text-gray-500">{anomalies.length} anomalous events</p>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead><tr className="table-header">
            <th className="px-4 py-3 text-left">Anomaly Score</th><th className="px-4 py-3 text-left">Risk Score</th>
            <th className="px-4 py-3 text-left">Severity</th><th className="px-4 py-3 text-left">Source</th>
            <th className="px-4 py-3 text-left">Destination</th><th className="px-4 py-3 text-left">Protocol</th>
          </tr></thead>
          <tbody>
            {anomalies.map((a) => (
              <tr key={a.id} className="table-row">
                <td className="px-4 py-3 font-mono text-orange-400">{a.anomaly_score.toFixed(4)}</td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2">
                    <div className="w-16 h-2 bg-gray-800 rounded-full overflow-hidden">
                      <div className={`h-full rounded-full ${a.risk_score > 75 ? 'bg-red-500' : a.risk_score > 50 ? 'bg-orange-500' : a.risk_score > 25 ? 'bg-yellow-500' : 'bg-green-500'}`}
                        style={{ width: `${Math.min(a.risk_score, 100)}%` }} />
                    </div>
                    <span className="text-xs text-gray-400">{a.risk_score.toFixed(1)}</span>
                  </div>
                </td>
                <td className="px-4 py-3"><span className={`badge severity-${a.severity || 'low'}`}>{a.severity || 'N/A'}</span></td>
                <td className="px-4 py-3 font-mono text-xs text-gray-400">{a.src_ip || '—'}</td>
                <td className="px-4 py-3 font-mono text-xs text-gray-400">{a.dst_ip || '—'}</td>
                <td className="px-4 py-3 text-gray-500">{a.protocol || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {anomalies.length === 0 && <p className="text-gray-600 text-sm text-center py-8">No anomalies detected</p>}
    </div>
  );
}

/* ---- Incidents Tab ---- */
function IncidentsTab({ incidents }: { incidents: Incident[] }) {
  return (
    <div className="space-y-4">
      <p className="text-sm text-gray-500">{incidents.length} correlated incidents</p>
      {incidents.map((inc) => (
        <div key={inc.id} className="card">
          <div className="flex items-start justify-between mb-3">
            <div>
              <h3 className="font-semibold text-white">{inc.name}</h3>
              <p className="text-sm text-gray-500 mt-1">{inc.description}</p>
            </div>
            <span className={`badge severity-${inc.severity || 'low'}`}>{inc.severity}</span>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-center">
            <div><p className="text-lg font-bold text-white">{inc.event_count}</p><p className="text-xs text-gray-500">Events</p></div>
            <div><p className="text-lg font-bold text-orange-400">{inc.risk_score?.toFixed(1)}</p><p className="text-xs text-gray-500">Risk Score</p></div>
            <div><p className="text-xs text-gray-400 font-mono">{inc.involved_ips?.sources?.join(', ') || '—'}</p><p className="text-xs text-gray-600">Sources</p></div>
            <div><p className="text-xs text-gray-400 font-mono">{inc.involved_ips?.destinations?.join(', ') || '—'}</p><p className="text-xs text-gray-600">Targets</p></div>
          </div>
          {inc.threat_categories && inc.threat_categories.length > 0 && (
            <div className="flex gap-2 mt-3">
              {inc.threat_categories.map((cat) => (
                <span key={cat} className="badge bg-red-500/10 text-red-400 border-red-500/20">{cat}</span>
              ))}
            </div>
          )}
        </div>
      ))}
      {incidents.length === 0 && <p className="text-gray-600 text-sm text-center py-8">No incidents. Run analysis first.</p>}
    </div>
  );
}

/* ---- Correlation Tab ---- */
function CorrelationTab({ incidents, evidence }: { incidents: Incident[]; evidence: Evidence[] }) {
  // Build a simple text-based correlation view since ForceGraph2D requires canvas
  const srcIps = [...new Set(evidence.map((e) => e.src_ip).filter(Boolean))];

  return (
    <div className="space-y-4">
      <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider">Evidence Correlation Map</h3>
      {srcIps.length > 0 ? (
        <div className="space-y-4">
          {srcIps.map((ip) => {
            const related = evidence.filter((e) => e.src_ip === ip);
            const dstIps = [...new Set(related.map((e) => e.dst_ip).filter(Boolean))];
            const threats = [...new Set(related.map((e) => e.predicted_threat).filter(Boolean))];
            return (
              <div key={ip} className="card border-l-4 border-l-cyber-accent">
                <div className="flex items-center gap-3 mb-3">
                  <Link2 className="w-4 h-4 text-cyber-accent" />
                  <span className="font-mono text-sm text-white">{ip}</span>
                  <span className="text-xs text-gray-500">→ {related.length} events</span>
                </div>
                <div className="ml-7 space-y-2">
                  <div className="flex flex-wrap gap-2">
                    {dstIps.map((dst) => (
                      <span key={dst} className="badge bg-purple-500/10 text-purple-400 border-purple-500/20 font-mono">→ {dst}</span>
                    ))}
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {threats.map((t) => (
                      <span key={t} className="badge bg-red-500/10 text-red-400 border-red-500/20">{t}</span>
                    ))}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      ) : <p className="text-gray-600 text-sm text-center py-8">No correlation data available</p>}
    </div>
  );
}

/* ---- Chain of Custody Tab ---- */
function CustodyTab({ evidence }: { evidence: Evidence[] }) {
  const [selected, setSelected] = useState<string | null>(null);
  const [chain, setChain] = useState<ChainOfCustodyEntry[]>([]);
  const [loadingChain, setLoadingChain] = useState(false);

  const loadChain = async (evId: string) => {
    setSelected(evId);
    setLoadingChain(true);
    try {
      const res = await evidenceApi.custody(evId);
      setChain(res.data);
    } catch (err) { console.error(err); }
    finally { setLoadingChain(false); }
  };

  return (
    <div className="space-y-4">
      <p className="text-sm text-gray-500">Select an evidence item to view its chain of custody.</p>
      <div className="grid lg:grid-cols-2 gap-6">
        {/* Evidence list */}
        <div className="space-y-2 max-h-[500px] overflow-y-auto">
          {evidence.slice(0, 50).map((e) => (
            <button key={e.id} onClick={() => loadChain(e.id)}
              className={`w-full text-left p-3 rounded-lg border transition-colors ${selected === e.id ? 'border-cyber-accent bg-cyber-accent/5' : 'border-gray-800 hover:border-gray-700'}`}>
              <p className="text-sm text-white truncate">{e.predicted_threat || e.evidence_type}</p>
              <p className="text-xs text-gray-500">{e.src_ip} → {e.dst_ip}</p>
            </button>
          ))}
          {evidence.length === 0 && <p className="text-gray-600 text-sm">No evidence</p>}
        </div>

        {/* Timeline */}
        <div className="card">
          <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-4">Chain of Custody Timeline</h3>
          {loadingChain ? (
            <div className="flex justify-center py-8"><div className="animate-spin w-6 h-6 border-2 border-cyber-accent border-t-transparent rounded-full" /></div>
          ) : chain.length > 0 ? (
            <div className="relative pl-6 space-y-6">
              <div className="absolute left-2 top-2 bottom-2 w-0.5 bg-gray-800" />
              {chain.map((c, i) => (
                <div key={c.id} className="relative animate-slide-in" style={{ animationDelay: `${i * 50}ms` }}>
                  <div className="absolute -left-[18px] top-1 w-3 h-3 rounded-full bg-cyber-accent border-2 border-cyber-dark" />
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-semibold text-white uppercase">{c.action}</span>
                      <span className="text-xs text-gray-600">by {c.username || 'system'}</span>
                    </div>
                    <p className="text-xs text-gray-500 mt-0.5">{c.description}</p>
                    <p className="text-[10px] text-gray-700 mt-1 flex items-center gap-1">
                      <Clock className="w-3 h-3" />
                      {new Date(c.timestamp).toLocaleString()}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-gray-600 text-sm text-center py-6">{selected ? 'No custody records' : 'Select evidence to view timeline'}</p>
          )}
        </div>
      </div>
    </div>
  );
}

/* ---- Reports Tab ---- */
function ReportsTab({ caseId }: { caseId: string }) {
  const [generating, setGenerating] = useState(false);
  const [reports, setReports] = useState<ReportInfo[]>([]);
  const [reportType, setReportType] = useState('pdf');
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // Load generated reports history
  useEffect(() => {
    reportsApi.list(caseId)
      .then((res) => setReports(res.data))
      .catch((err) => {
        console.error('Failed to load reports:', err);
        setError('Failed to load report history.');
      });
  }, [caseId]);

  const handleGenerate = async () => {
    setGenerating(true);
    setError(null);
    setSuccess(null);
    try {
      const res = await reportsApi.generate(caseId, reportType);
      setReports((prev) => [res.data, ...prev]);
      setSuccess(`Forensic report (${reportType.toUpperCase()}) generated successfully!`);
    } catch (err: any) {
      console.error(err);
      setError(err.response?.data?.detail || 'Failed to generate forensic report.');
    } finally {
      setGenerating(false);
    }
  };

  const handleDownload = async (reportId: string, type: string) => {
    setError(null);
    try {
      const res = await reportsApi.download(reportId);
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const a = document.createElement('a');
      a.href = url;
      a.download = `forensic_report.${type}`;
      a.click();
      window.URL.revokeObjectURL(url);
    } catch (err: any) {
      console.error(err);
      setError('Failed to download report file.');
    }
  };

  return (
    <div className="space-y-6">
      {error && (
        <div className="p-3 bg-red-500/10 border border-red-500/20 text-red-400 rounded-lg text-sm animate-fade-in">
          {error}
        </div>
      )}
      {success && (
        <div className="p-3 bg-green-500/10 border border-green-500/20 text-green-400 rounded-lg text-sm animate-fade-in">
          {success}
        </div>
      )}

      <div className="card">
        <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-4">Generate Forensic Report</h3>
        <div className="flex items-center gap-4">
          <select value={reportType} onChange={(e) => setReportType(e.target.value)} className="input-field">
            <option value="pdf">PDF Report</option>
            <option value="json">JSON Export</option>
            <option value="csv">CSV Export</option>
          </select>
          <button onClick={handleGenerate} disabled={generating} className="btn-primary flex items-center gap-2">
            <FileText className="w-4 h-4" />
            {generating ? 'Generating...' : 'Generate Report'}
          </button>
        </div>
      </div>

      {reports.length > 0 && (
        <div className="card">
          <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-4">Generated Reports</h3>
          <div className="space-y-2">
            {reports.map((r) => (
              <div key={r.id} className="flex items-center justify-between py-3 px-4 bg-gray-800/30 rounded-lg">
                <div>
                  <p className="text-sm text-white">Forensic Report ({r.report_type.toUpperCase()})</p>
                  <p className="text-xs text-gray-500">{new Date(r.generated_at).toLocaleString()}</p>
                </div>
                <button onClick={() => handleDownload(r.id, r.report_type)} className="btn-secondary flex items-center gap-2 text-sm">
                  <Download className="w-4 h-4" /> Download
                </button>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
