/** Model Performance page — view trained model metrics and feature importance. */

import { useEffect, useState } from 'react';
import { modelsApi } from '../api/client';
import type { ModelVersion } from '../types';
import { Cpu } from 'lucide-react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer,
} from 'recharts';

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
        <h1 className="text-2xl font-bold text-white">Model Performance</h1>
        <p className="text-gray-500 text-sm mt-1">Trained ML model metrics — all values from actual model execution</p>
      </div>

      {models.length === 0 ? (
        <div className="card text-center py-16">
          <Cpu className="w-12 h-12 text-gray-700 mx-auto mb-4" />
          <p className="text-gray-500">No trained models found. Train models using: <code className="text-cyber-accent">python -m ml.training.train</code></p>
        </div>
      ) : (
        models.map((m) => (
          <div key={m.id} className="card space-y-4">
            <div className="flex items-start justify-between">
              <div>
                <h2 className="text-lg font-bold text-white">{m.algorithm}</h2>
                <p className="text-sm text-gray-500">Version {m.version} • {m.dataset_name || 'Unknown dataset'}</p>
                <p className="text-xs text-gray-600">Trained: {new Date(m.trained_at).toLocaleString()}</p>
              </div>
              <span className={`badge ${m.status === 'active' ? 'severity-low' : 'bg-gray-700 text-gray-400 border-gray-600'}`}>{m.status}</span>
            </div>

            {/* Metrics */}
            {m.metrics && (
              <div>
                <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">Evaluation Metrics</h3>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  {Object.entries(m.metrics).filter(([k]) => 
                    ['accuracy', 'precision', 'recall', 'f1_score', 'roc_auc', 'pr_auc'].includes(k)
                  ).map(([key, val]) => (
                    <div key={key} className="bg-gray-800/50 rounded-lg p-3 text-center">
                      <p className="text-xs text-gray-500 uppercase">{key.replace(/_/g, ' ')}</p>
                      <p className="text-xl font-bold text-white">{typeof val === 'number' ? (val * 100).toFixed(1) + '%' : String(val)}</p>
                    </div>
                  ))}
                  {m.metrics.train_time_seconds && (
                    <div className="bg-gray-800/50 rounded-lg p-3 text-center">
                      <p className="text-xs text-gray-500 uppercase">Train Time</p>
                      <p className="text-xl font-bold text-white">{m.metrics.train_time_seconds}s</p>
                    </div>
                  )}
                  {m.metrics.records_per_second && (
                    <div className="bg-gray-800/50 rounded-lg p-3 text-center">
                      <p className="text-xs text-gray-500 uppercase">Throughput</p>
                      <p className="text-xl font-bold text-white">{m.metrics.records_per_second} rec/s</p>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Feature Importance (for Random Forest) */}
            {m.metrics?.feature_importance && (
              <div>
                <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">
                  Feature Importance
                  <span className="text-xs font-normal text-gray-600 ml-2">(model-level importance, not causal)</span>
                </h3>
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart
                    data={Object.entries(m.metrics.feature_importance)
                      .slice(0, 15)
                      .map(([name, value]) => ({ name: name.trim(), value: Number(value) }))}
                    layout="vertical"
                  >
                    <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
                    <XAxis type="number" tick={{ fontSize: 10 }} />
                    <YAxis type="category" dataKey="name" tick={{ fontSize: 9 }} width={180} />
                    <Tooltip contentStyle={{ background: '#111827', border: '1px solid #374151', borderRadius: '8px' }} />
                    <Bar dataKey="value" fill="#3b82f6" radius={[0, 4, 4, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            )}

            {/* Parameters */}
            {m.parameters && (
              <div>
                <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-2">Hyperparameters</h3>
                <div className="flex flex-wrap gap-2">
                  {Object.entries(m.parameters).map(([k, v]) => (
                    <span key={k} className="text-xs bg-gray-800 text-gray-400 px-3 py-1 rounded-full">
                      {k}: {String(v)}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Features */}
            {m.features && (
              <div>
                <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-2">Features Used ({m.features.length})</h3>
                <div className="flex flex-wrap gap-1.5">
                  {m.features.map((f) => (
                    <span key={f} className="text-[10px] bg-gray-800/50 text-gray-500 px-2 py-0.5 rounded font-mono">{f.trim()}</span>
                  ))}
                </div>
              </div>
            )}
          </div>
        ))
      )}
    </div>
  );
}
