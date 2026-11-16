import React, { useState, useEffect } from 'react';
import {
  History,
  Trash2,
  ExternalLink,
  ShieldAlert,
  Calendar,
  AlertTriangle,
  RotateCcw,
  CheckCircle2,
  ChevronRight,
  Filter
} from 'lucide-react';
import { api } from '../services/api';
import { IncidentSummary, IncidentDetail } from '../types';
import { Badge } from '../components/common/Badge';
import { Modal } from '../components/common/Modal';
import { RiskMeter } from '../components/common/RiskMeter';

interface IncidentHistoryPageProps {
  initialOpenId?: string;
}

export const IncidentHistoryPage: React.FC<IncidentHistoryPageProps> = ({ initialOpenId }) => {
  const [history, setHistory] = useState<IncidentSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedIncident, setSelectedIncident] = useState<IncidentDetail | null>(null);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [showClearConfirm, setShowClearConfirm] = useState(false);
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const fetchHistory = async () => {
    setLoading(true);
    try {
      const data = await api.getHistory();
      setHistory(data);
    } catch (err) {
      console.error('Failed to load incident history:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, []);

  useEffect(() => {
    if (initialOpenId) {
      handleOpenDetail(initialOpenId);
    }
  }, [initialOpenId]);

  const handleOpenDetail = async (id: string) => {
    setLoadingDetail(true);
    try {
      const detail = await api.getIncidentDetail(id);
      setSelectedIncident(detail);
    } catch (err: any) {
      alert('Failed to load incident details: ' + (err.message || 'Error'));
    } finally {
      setLoadingDetail(false);
    }
  };

  const handleDelete = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!confirm('Are you sure you want to delete this incident record?')) return;
    try {
      await api.deleteIncident(id);
      setHistory((prev) => prev.filter((item) => item.id !== id));
      if (selectedIncident?.id === id) {
        setSelectedIncident(null);
      }
    } catch (err) {
      console.error(err);
      alert('Delete failed');
    }
  };

  const handleClearAll = async () => {
    try {
      await api.clearHistory();
      setHistory([]);
      setShowClearConfirm(false);
      setSelectedIncident(null);
    } catch (err) {
      console.error(err);
      alert('Failed to clear history');
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-slate-900 dark:text-white">
            Incident Diagnosis History
          </h2>
          <p className="text-sm text-slate-600 dark:text-slate-300 mt-1">
            Audit logs of previous evaluations performed by CyberMate's deterministic expert engine.
          </p>
        </div>

        {history.length > 0 && (
          <button
            onClick={() => setShowClearConfirm(true)}
            className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/20 border border-red-200 dark:border-red-900/30 transition-colors self-start sm:self-auto"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span>Clear All History</span>
          </button>
        )}
      </div>

      {/* History Table / Cards */}
      {loading ? (
        <div className="space-y-3">
          {[1, 2, 3, 4].map((n) => (
            <div key={n} className="h-20 rounded-xl bg-slate-100 dark:bg-cyber-surface animate-pulse" />
          ))}
        </div>
      ) : history.length > 0 ? (
        <div className="rounded-xl border border-slate-200 dark:border-cyber-border bg-white dark:bg-cyber-surface overflow-hidden shadow-sm">
          <div className="divide-y divide-slate-100 dark:divide-cyber-border">
            {history.map((item) => {
              const formattedDate = item.timestamp
                ? new Date(item.timestamp).toLocaleString(undefined, {
                    month: 'short',
                    day: 'numeric',
                    hour: '2-digit',
                    minute: '2-digit'
                  })
                : '—';

              return (
                <div
                  key={item.id}
                  onClick={() => handleOpenDetail(item.id)}
                  className="p-4 sm:px-6 hover:bg-slate-50 dark:hover:bg-cyber-elevated/50 transition-colors cursor-pointer flex flex-col sm:flex-row sm:items-center justify-between gap-4"
                >
                  <div className="space-y-1.5 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-semibold text-sm text-slate-900 dark:text-slate-100">
                        {item.title}
                      </span>
                      <Badge variant="severity" severity={item.severity} size="sm" />
                      <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-slate-100 dark:bg-cyber-elevated text-slate-500">
                        {item.input_method}
                      </span>
                    </div>

                    <div className="flex items-center space-x-3 text-xs text-slate-500 dark:text-slate-400">
                      <span>{item.primary_threat}</span>
                      <span>•</span>
                      <span>{formattedDate}</span>
                    </div>
                  </div>

                  <div className="flex items-center space-x-5 shrink-0">
                    <div className="text-right text-xs">
                      <div className="font-mono font-semibold text-slate-800 dark:text-slate-200">
                        Risk {item.risk_score}
                      </div>
                      <div className="text-[11px] font-mono text-slate-400">
                        {Math.round(item.confidence * 100)}% conf
                      </div>
                    </div>

                    <button
                      onClick={(e) => handleDelete(item.id, e)}
                      className="p-1.5 rounded-lg text-slate-400 hover:text-red-500 hover:bg-slate-100 dark:hover:bg-cyber-elevated transition-colors"
                      title="Delete record"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>

                    <ChevronRight className="w-4 h-4 text-slate-400" />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      ) : (
        <div className="p-12 text-center rounded-xl border border-dashed border-slate-200 dark:border-cyber-border bg-white/50 dark:bg-cyber-surface/50 space-y-3">
          <History className="w-8 h-8 text-slate-400 mx-auto" />
          <h4 className="text-sm font-semibold text-slate-800 dark:text-slate-200">
            No Saved Incident Records
          </h4>
          <p className="text-xs text-slate-500 dark:text-slate-400 max-w-sm mx-auto">
            Analyses conducted through structured forms or chat will automatically be recorded in your local SQLite audit database.
          </p>
        </div>
      )}

      {/* Incident Detail Modal */}
      {selectedIncident && (
        <Modal
          isOpen={Boolean(selectedIncident)}
          onClose={() => setSelectedIncident(null)}
          title={selectedIncident.title}
          subtitle={`Incident Record • ${selectedIncident.primary_threat}`}
          maxWidth="2xl"
        >
          <div className="space-y-6 text-sm">
            {/* Summary Header */}
            <div className="flex flex-wrap items-center gap-3 pb-3 border-b border-slate-100 dark:border-cyber-border">
              <Badge variant="severity" severity={selectedIncident.severity} />
              <Badge variant="risk" risk={selectedIncident.risk_level} />
              <span className="text-xs font-mono text-slate-500">
                Confidence: {Math.round(selectedIncident.confidence * 100)}% ({selectedIncident.confidence_label})
              </span>
              <span className="text-xs font-mono text-slate-400">
                Method: {selectedIncident.input_method}
              </span>
            </div>

            {/* Explanation & Evidence */}
            {selectedIncident.report.primary_threat && (
              <div className="space-y-2">
                <h4 className="text-xs font-mono uppercase tracking-wider text-slate-400">
                  Observed Rule Evidence
                </h4>
                <div className="space-y-1.5">
                  {selectedIncident.report.primary_threat.evidence.map((ev, i) => (
                    <div key={i} className="flex items-start space-x-2 text-xs text-slate-700 dark:text-slate-300">
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500 shrink-0 mt-0.5" />
                      <span>{ev}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Prescribed Defensive Actions */}
            <div className="space-y-2">
              <h4 className="text-xs font-mono uppercase tracking-wider text-slate-400">
                Recommended Defensive Response
              </h4>
              <ol className="space-y-1.5 text-xs text-slate-700 dark:text-slate-300">
                {selectedIncident.report.overall_recommendations.map((rec, i) => (
                  <li key={i} className="flex items-start space-x-2">
                    <span className="font-bold text-emerald-600 dark:text-emerald-400 font-mono">
                      {i + 1}.
                    </span>
                    <span>{rec}</span>
                  </li>
                ))}
              </ol>
            </div>

            {/* Evaluated Facts (Raw facts dump) */}
            <div className="space-y-2 pt-2 border-t border-slate-100 dark:border-cyber-border">
              <h4 className="text-xs font-mono uppercase tracking-wider text-slate-400">
                Evaluated Incident Facts
              </h4>
              <pre className="p-3 rounded-lg bg-slate-900 text-slate-300 text-xs font-mono overflow-x-auto max-h-40">
                {JSON.stringify(selectedIncident.facts, null, 2)}
              </pre>
            </div>
          </div>
        </Modal>
      )}

      {/* Clear History Confirmation Dialog */}
      {showClearConfirm && (
        <Modal
          isOpen={showClearConfirm}
          onClose={() => setShowClearConfirm(false)}
          title="Confirm Clear Audit History"
          maxWidth="sm"
        >
          <div className="space-y-4 text-xs">
            <p className="text-slate-600 dark:text-slate-300 leading-relaxed">
              Are you sure you want to clear all analyzed security incidents from the local SQLite database? This action cannot be undone.
            </p>
            <div className="flex justify-end space-x-3 pt-2">
              <button
                type="button"
                onClick={() => setShowClearConfirm(false)}
                className="px-3 py-1.5 rounded-lg border border-slate-200 dark:border-cyber-border text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-cyber-elevated font-medium"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleClearAll}
                className="px-3 py-1.5 rounded-lg bg-red-600 hover:bg-red-500 text-white font-medium shadow-sm"
              >
                Yes, Clear All
              </button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
};
