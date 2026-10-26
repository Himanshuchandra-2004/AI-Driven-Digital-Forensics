/** Cases list — highlighted "New Case" call-to-action over an analysis backdrop. */

import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { casesApi } from '../api/client';
import { useAuth } from '../context/AuthContext';
import type { Case } from '../types';
import { Plus, FolderOpen, Trash2, AlertTriangle } from 'lucide-react';

export default function CasesPage() {
  const { user } = useAuth();
  const [cases, setCases] = useState<Case[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({ name: '', description: '' });
  const [creating, setCreating] = useState(false);
  const [deletingCase, setDeletingCase] = useState<Case | null>(null);
  const [deleting, setDeleting] = useState(false);

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

  const handleDelete = async () => {
    if (!deletingCase) return;
    setDeleting(true);
    try {
      await casesApi.delete(deletingCase.id);
      setDeletingCase(null);
      loadCases();
    } catch (err) {
      console.error('Failed to delete case:', err);
    } finally {
      setDeleting(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="page-title">Forensic Cases</h1>
          <p className="text-gray-500 text-sm mt-1">Manage investigation cases</p>
        </div>
        {user?.role === 'admin' && (
          <span className="badge bg-red-500/10 text-red-400 border-red-500/30 text-xs uppercase">
            Admin Privileges Active
          </span>
        )}
      </div>

      {/* Highlighted New Case box */}
      <button onClick={() => setShowCreate(true)} className="newcase-box group">
        <span className="newcase-icon"><Plus className="w-7 h-7" /></span>
        <span className="text-left">
          <span className="block text-xl font-bold">New Case</span>
          <span className="block text-sm opacity-80">Start a new forensic investigation — upload evidence and let the AI analyze it</span>
        </span>
      </button>

      {/* Create Case Modal */}
      {showCreate && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4" onClick={() => setShowCreate(false)}>
          <form onClick={(e) => e.stopPropagation()} onSubmit={handleCreate} className="card w-full max-w-lg space-y-4 glow-border">
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

      {/* Delete Confirmation Modal (Admin Only) */}
      {deletingCase && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4" onClick={() => setDeletingCase(null)}>
          <div onClick={(e) => e.stopPropagation()} className="card w-full max-w-md space-y-4 border-red-500/40 shadow-2xl shadow-red-950/50">
            <div className="flex items-center gap-3 text-red-400">
              <div className="p-2 rounded-lg bg-red-500/10 border border-red-500/20">
                <AlertTriangle className="w-6 h-6" />
              </div>
              <h2 className="text-lg font-bold text-white">Delete Case Permanently?</h2>
            </div>
            <p className="text-sm text-gray-300">
              Are you sure you want to delete <span className="text-white font-semibold">"{deletingCase.name}"</span>?
            </p>
            <p className="text-xs text-gray-400 bg-red-500/10 p-3 rounded border border-red-500/20">
              ⚠️ This action cannot be undone. All associated network evidence records, machine learning threat classifications, anomaly detections, and generated reports will be permanently deleted.
            </p>
            <div className="flex justify-end gap-3 pt-2">
              <button type="button" onClick={() => setDeletingCase(null)} className="btn-secondary text-sm">
                Cancel
              </button>
              <button
                type="button"
                onClick={handleDelete}
                disabled={deleting}
                className="px-4 py-2 rounded-lg bg-red-500/20 hover:bg-red-500/30 text-red-300 border border-red-500/40 text-sm font-medium transition-colors"
              >
                {deleting ? 'Deleting...' : 'Confirm Delete'}
              </button>
            </div>
          </div>
        </div>
      )}

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
            <Link key={c.id} to={`/cases/${c.id}`} className="card hover:border-cyber-accent/60 flex items-center justify-between group">
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

              <div className="flex items-center gap-6 ml-4">
                <div className="flex items-center gap-6 text-center">
                  <div><p className="text-lg font-bold text-white">{c.evidence_count}</p><p className="text-xs text-gray-600">Evidence</p></div>
                  <div><p className="text-lg font-bold text-red-400">{c.threat_count}</p><p className="text-xs text-gray-600">Threats</p></div>
                  <div><p className="text-lg font-bold text-orange-400">{c.anomaly_count}</p><p className="text-xs text-gray-600">Anomalies</p></div>
                </div>

                {user?.role === 'admin' && (
                  <button
                    onClick={(e) => {
                      e.preventDefault();
                      e.stopPropagation();
                      setDeletingCase(c);
                    }}
                    className="p-2 text-gray-500 hover:text-red-400 hover:bg-red-500/10 rounded-lg transition-colors border border-transparent hover:border-red-500/20"
                    title="Delete Case (Admin Only)"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                )}
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
