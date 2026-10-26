/** Model Performance — metric rings, charts, dropdown details, Isolation Forest explainer. */

import { useEffect, useState } from 'react';
import { modelsApi } from '../api/client';
import type { ModelVersion } from '../types';
import { Cpu, TreeDeciduous } from 'lucide-react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell,
  RadarChart, PolarGrid, PolarAngleAxis, Radar,
} from 'recharts';
import Accordion from '../components/ui/Accordion';
import IsolationViz from '../components/ui/IsolationViz';

const METRIC_KEYS = ['accuracy', 'precision', 'recall', 'f1_score', 'roc_auc', 'pr_auc'];
const COLORS = ['#22d3ee', '#3b82f6', '#6366f1', '#14b8a6', '#0ea5e9', '#8b5cf6'];
const TIP = { background: 'rgba(4,8,16,.96)', border: '1px solid rgba(34,211,238,.5)', borderRadius: '10px', color: '#e6f0ff' };
const label = (k: string) => k.replace(/_/g, ' ').replace('roc auc', 'ROC AUC').replace('pr auc', 'PR AUC');

function Ring({ name, value, color }: { name: string; value: number; color: string }) {
  const C = 2 * Math.PI * 34;
  const pct = Math.max(0, Math.min(1, value));
  return (
    <div className="metric-tile">
      <svg viewBox="0 0 80 80" width="84" height="84">
        <circle cx="40" cy="40" r="34" fill="none" stroke="currentColor" strokeOpacity=".12" strokeWidth="7" />
        <circle cx="40" cy="40" r="34" fill="none" stroke={color} strokeWidth="7" strokeLinecap="round"
          strokeDasharray={`${pct * C} ${C}`} transform="rotate(-90 40 40)" className="ring-draw" style={{ filter: `drop-shadow(0 0 5px ${color})` }} />
        <text x="40" y="45" textAnchor="middle" fontSize="15" fontWeight="700" fill="currentColor">{(pct * 100).toFixed(1)}</text>
      </svg>
      <p className="text-[11px] text-gray-500 uppercase tracking-wider mt-1">{label(name)}</p>
    </div>
  );
}

export default function ModelsPage() {
  const [models, setModels] = useState<ModelVersion[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    modelsApi.list().then((r) => setModels(r.data)).catch(console.error).finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="flex justify-center py-20"><div className="animate-spin w-8 h-8 border-2 border-cyber-accent border-t-transparent rounded-full" /></div>;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="page-title">Model Performance</h1>
        <p className="text-gray-500 text-sm mt-1">Trained ML model metrics — all values from actual model execution</p>
      </div>

      {models.length === 0 ? (
        <div className="card text-center py-16">
          <Cpu className="w-12 h-12 text-gray-700 mx-auto mb-4" />
          <p className="text-gray-500">No trained models found. Train models using: <code className="text-cyber-accent">python -m ml.training.train</code></p>
        </div>
      ) : (
        models.map((m) => {
          const metricList = Object.entries(m.metrics || {})
            .filter(([k, v]) => METRIC_KEYS.includes(k) && typeof v === 'number')
            .map(([k, v]) => ({ key: k, name: label(k), value: v as number, pct: Math.round((v as number) * 1000) / 10 }));
          const isIso = m.algorithm.toLowerCase().includes('isolation');
          const importance = m.metrics?.feature_importance
            ? Object.entries(m.metrics.feature_importance).slice(0, 15).map(([name, value]) => ({ name: name.trim(), value: Number(value) }))
            : [];

          return (
            <div key={m.id} className="card space-y-6">
              <div className="flex items-start justify-between">
                <div>
                  <h2 className="text-xl font-bold text-white">{m.algorithm}</h2>
                  <p className="text-sm text-gray-500">Version {m.version} • {m.dataset_name || 'Unknown dataset'}</p>
                  <p className="text-xs text-gray-600">Trained: {new Date(m.trained_at).toLocaleString()}</p>
                </div>
                <span className={`badge ${m.status === 'active' ? 'severity-low' : 'bg-gray-700 text-gray-400 border-gray-600'}`}>{m.status}</span>
              </div>

              {metricList.length > 0 && (
                <>
                  <div className="grid grid-cols-3 md:grid-cols-6 gap-3">
                    {metricList.map((x, i) => <Ring key={x.key} name={x.key} value={x.value} color={COLORS[i % COLORS.length]} />)}
                  </div>

                  <div className="grid lg:grid-cols-2 gap-6">
                    <div>
                      <h3 className="card-title">Metric Comparison</h3>
                      <ResponsiveContainer width="100%" height={250}>
                        <BarChart data={metricList}>
                          <defs>{COLORS.map((c, i) => (
                            <linearGradient key={c} id={`mg${m.id}${i}`} x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor={c} /><stop offset="1" stopColor={c} stopOpacity={0.2} /></linearGradient>
                          ))}</defs>
                          <CartesianGrid strokeDasharray="3 6" vertical={false} />
                          <XAxis dataKey="name" tick={{ fontSize: 10 }} />
                          <YAxis domain={[0, 100]} tick={{ fontSize: 10 }} unit="%" />
                          <Tooltip contentStyle={TIP} cursor={{ fill: 'rgba(0,200,255,.08)' }} formatter={(v: number) => `${v}%`} />
                          <Bar dataKey="pct" radius={[10, 10, 0, 0]} animationDuration={1400} className="glow-svg">
                            {metricList.map((_, i) => <Cell key={i} fill={`url(#mg${m.id}${i % COLORS.length})`} stroke={COLORS[i % COLORS.length]} />)}
                          </Bar>
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                    <div>
                      <h3 className="card-title">Performance Radar</h3>
                      <ResponsiveContainer width="100%" height={250}>
                        <RadarChart data={metricList} outerRadius="72%">
                          <PolarGrid stroke="rgba(0,200,255,.25)" />
                          <PolarAngleAxis dataKey="name" tick={{ fontSize: 10 }} />
                          <Radar dataKey="pct" stroke="#00c8ff" strokeWidth={2.5} fill="#00c8ff" fillOpacity={0.3} animationDuration={1400} className="glow-svg" />
                          <Tooltip contentStyle={TIP} formatter={(v: number) => `${v}%`} />
                        </RadarChart>
                      </ResponsiveContainer>
                    </div>
                  </div>
                </>
              )}

              {(m.metrics?.train_time_seconds || m.metrics?.records_per_second) && (
                <div className="flex flex-wrap gap-3 text-sm">
                  {m.metrics?.train_time_seconds && <span className="chip">Train time: <b>{m.metrics.train_time_seconds}s</b></span>}
                  {m.metrics?.records_per_second && <span className="chip">Throughput: <b>{m.metrics.records_per_second} rec/s</b></span>}
                </div>
              )}

              {isIso && (
                <div className="iso-card">
                  <h3 className="card-title flex items-center gap-2"><TreeDeciduous className="w-4 h-4" /> How Isolation Forest finds anomalies</h3>
                  <IsolationViz contamination={m.parameters?.contamination} />
                </div>
              )}

              {importance.length > 0 && (
                <div>
                  <h3 className="card-title">Feature Importance <span className="text-xs font-normal text-gray-600 normal-case tracking-normal ml-2">(model-level importance, not causal)</span></h3>
                  <ResponsiveContainer width="100%" height={320}>
                    <BarChart data={importance} layout="vertical">
                      <defs><linearGradient id={`fi${m.id}`} x1="0" y1="0" x2="1" y2="0"><stop offset="0" stopColor="#4a5bff" stopOpacity={0.4} /><stop offset="1" stopColor="#00c8ff" /></linearGradient></defs>
                      <CartesianGrid strokeDasharray="3 6" horizontal={false} />
                      <XAxis type="number" tick={{ fontSize: 10 }} />
                      <YAxis type="category" dataKey="name" tick={{ fontSize: 9 }} width={180} />
                      <Tooltip contentStyle={TIP} cursor={{ fill: 'rgba(0,200,255,.08)' }} />
                      <Bar dataKey="value" fill={`url(#fi${m.id})`} radius={[0, 8, 8, 0]} animationDuration={1400} className="glow-svg" />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}

              <div className="space-y-3">
                {m.parameters && (
                  <Accordion title="Hyperparameters" count={Object.keys(m.parameters).length}>
                    <div className="grid sm:grid-cols-2 gap-2">
                      {Object.entries(m.parameters).map(([k, v]) => (
                        <div key={k} className="flex justify-between gap-3 px-3 py-2 rounded-lg bg-gray-800/30 text-sm">
                          <span className="text-gray-500 font-mono">{k}</span><b className="text-white font-mono">{String(v)}</b>
                        </div>
                      ))}
                    </div>
                  </Accordion>
                )}
                {m.features && (
                  <Accordion title="Features Used" count={m.features.length}>
                    <div className="flex flex-wrap gap-2">
                      {m.features.map((f) => <span key={f} className="chip font-mono text-[11px]">{f.trim()}</span>)}
                    </div>
                  </Accordion>
                )}
              </div>
            </div>
          );
        })
      )}
    </div>
  );
}
