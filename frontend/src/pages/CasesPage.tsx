/** Cases list — create, view, manage forensic cases. */

import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { casesApi } from '../api/client';
import type { Case } from '../types';
import { Plus, FolderOpen } from 'lucide-react';

export default function CasesPage() {
  const [cases, setCases] = useState<Case[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({ name: '', description: '' });
  const [creating, setCreating] = useState(false);

  const loadCases = () => {
    casesApi.list().then((r) => setCases(r.data)).catch(console.error).finally(() => setLoading(false));
  };

  useEffect(loadCases, []);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreating(true);
    try {
      await casesApi.create(form);
      setForm({ name: '', description: '' });
      setShowCreate(false);
      loadCases();
    } catch (err) {
      console.error(err);
    } finally {
      setCreating(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-white">Forensic Cases</h1>
          <p className="text-gray-500 text-sm mt-1">Manage investigation cases</p>
        </div>
        <button onClick={() => setShowCreate(true)} className="btn-primary flex items-center gap-2">
          <Plus className="w-4 h-4" /> New Case
        </button>
      </div>

      {/* Create Modal */}
      {showCreate && (
        <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4" onClick={() => setShowCreate(false)}>
          <form onClick={(e) => e.stopPropagation()} onSubmit={handleCreate} className="card w-full max-w-lg space-y-4">
            <h2 className="text-lg font-semibold text-white">Create New Case</h2>
            <div>
              <label className="block text-sm text-gray-400 mb-1">Case Name</label>
              <input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })}
                className="input-field w-full" placeholder="e.g., Network Intrusion Investigation" required />
            </div>
            <div>
              <label className="block text-sm text-gray-400 mb-1">Description</label>
              <textarea value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })}
                className="input-field w-full h-24 resize-none" placeholder="Case description..." />
            </div>
            <div className="flex justify-end gap-3">
              <button type="button" onClick={() => setShowCreate(false)} className="btn-secondary">Cancel</button>
              <button type="submit" disabled={creating} className="btn-primary">{creating ? 'Creating...' : 'Create Case'}</button>
            </div>
          </form>
        </div>
      )}

      {/* Cases list */}
      {loading ? (
        <div className="flex justify-center py-12"><div className="animate-spin w-8 h-8 border-2 border-cyber-accent border-t-transparent rounded-full" /></div>
      ) : cases.length === 0 ? (
        <div className="card text-center py-16">
          <FolderOpen className="w-12 h-12 text-gray-700 mx-auto mb-4" />
          <p className="text-gray-500">No cases yet. Create a new case or load a demo.</p>
        </div>
      ) : (
        <div className="grid gap-4">
          {cases.map((c) => (
            <Link key={c.id} to={`/cases/${c.id}`} className="card hover:border-cyber-accent/30 flex items-center justify-between group">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-3 mb-1">
                  <h3 className="font-semibold text-white truncate group-hover:text-cyber-accent transition-colors">{c.name}</h3>
                  {c.severity && <span className={`badge severity-${c.severity}`}>{c.severity}</span>}
                </div>
                <p className="text-sm text-gray-500 truncate">{c.description || 'No description'}</p>
                <div className="flex items-center gap-4 mt-2 text-xs text-gray-600">
                  <span>{new Date(c.created_at).toLocaleDateString()}</span>
                  <span>Status: {c.status}</span>
                  {c.investigator && <span>By: {c.investigator}</span>}
                </div>
              </div>
              <div className="flex items-center gap-6 text-center ml-4">
                <div><p className="text-lg font-bold text-white">{c.evidence_count}</p><p className="text-xs text-gray-600">Evidence</p></div>
                <div><p className="text-lg font-bold text-red-400">{c.threat_count}</p><p className="text-xs text-gray-600">Threats</p></div>
                <div><p className="text-lg font-bold text-orange-400">{c.anomaly_count}</p><p className="text-xs text-gray-600">Anomalies</p></div>
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
