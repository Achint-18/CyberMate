import React, { useEffect, useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  MessageSquareText,
  AlertTriangle,
  History,
  Activity,
  ArrowRight,
  RefreshCw,
  FileText
} from 'lucide-react';
import { api } from '../services/api';
import { DashboardMetrics, IncidentSummary } from '../types';
import { Badge } from '../components/common/Badge';
import { RiskMeter } from '../components/common/RiskMeter';
import { PageId } from '../components/common/Sidebar';

interface DashboardPageProps {
  onNavigate: (page: PageId, incidentId?: string) => void;
}

export const DashboardPage: React.FC<DashboardPageProps> = ({ onNavigate }) => {
  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchMetrics = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getDashboardMetrics();
      setMetrics(data);
    } catch (err: any) {
      console.error(err);
      setError('Unable to connect to CyberMate backend service.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchMetrics();
  }, []);

  return (
    <div className="space-y-8">
      {/* Hero / Main CTA Section */}
      <div className="rounded-xl border border-slate-200 dark:border-cyber-border bg-gradient-to-r from-slate-50 to-white dark:from-cyber-surface dark:to-cyber-elevated p-6 lg:p-8">
        <div className="max-w-3xl">
          <div className="inline-flex items-center space-x-2 px-2.5 py-1 rounded-md bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20 text-xs font-mono mb-3">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
            <span>Deterministic Expert System Ready</span>
          </div>
          <h2 className="text-2xl lg:text-3xl font-bold tracking-tight text-slate-900 dark:text-white">
            Practical Defensive Cybersecurity Reasoning
          </h2>
          <p className="mt-2 text-sm lg:text-base text-slate-600 dark:text-slate-300 leading-relaxed">
            Diagnose suspicious behaviors, identify likely threat classifications, calculate transparent risk scores, and generate prescriptive defensive mitigations using a 49-rule inference engine.
          </p>

          <div className="mt-6 flex flex-wrap gap-3">
            <button
              onClick={() => onNavigate('analyze')}
              className="inline-flex items-center space-x-2 px-4 py-2.5 rounded-lg text-sm font-medium bg-emerald-600 hover:bg-emerald-500 text-white shadow-sm transition-all focus:ring-2 focus:ring-emerald-500 focus:outline-none"
            >
              <ShieldAlert className="w-4 h-4" />
              <span>Analyze Security Incident</span>
              <ArrowRight className="w-4 h-4 ml-1" />
            </button>

            <button
              onClick={() => onNavigate('chat')}
              className="inline-flex items-center space-x-2 px-4 py-2.5 rounded-lg text-sm font-medium bg-white dark:bg-cyber-surface hover:bg-slate-50 dark:hover:bg-cyber-elevated text-slate-800 dark:text-slate-200 border border-slate-200 dark:border-cyber-border shadow-sm transition-all"
            >
              <MessageSquareText className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
              <span>Start Chat Diagnosis</span>
            </button>
          </div>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-5 rounded-xl border border-slate-200 dark:border-cyber-border bg-white dark:bg-cyber-surface">
          <div className="flex items-center justify-between text-slate-500 dark:text-slate-400 text-xs font-mono uppercase tracking-wider">
            <span>Overall Risk Score</span>
            <Activity className="w-4 h-4 text-emerald-500" />
          </div>
          <div className="mt-3 flex items-baseline space-x-2">
            <span className="text-2xl font-bold font-mono text-slate-900 dark:text-slate-100">
              {metrics ? metrics.overall_risk_score : '—'}
            </span>
            <span className="text-xs text-slate-400 font-mono">/ 100</span>
          </div>
          <div className="mt-2 text-xs">
            {metrics ? (
              <Badge variant="risk" risk={metrics.overall_risk_level} size="sm">
                {metrics.overall_risk_level} Risk Level
              </Badge>
            ) : (
              <span className="text-slate-400">Loading...</span>
            )}
          </div>
        </div>

        <div className="p-5 rounded-xl border border-slate-200 dark:border-cyber-border bg-white dark:bg-cyber-surface">
          <div className="flex items-center justify-between text-slate-500 dark:text-slate-400 text-xs font-mono uppercase tracking-wider">
            <span>Incidents Analyzed</span>
            <FileText className="w-4 h-4 text-slate-400" />
          </div>
          <div className="mt-3 flex items-baseline space-x-2">
            <span className="text-2xl font-bold font-mono text-slate-900 dark:text-slate-100">
              {metrics ? metrics.incidents_analyzed : '—'}
            </span>
          </div>
          <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
            Stored in local audit database
          </p>
        </div>

        <div className="p-5 rounded-xl border border-slate-200 dark:border-cyber-border bg-white dark:bg-cyber-surface">
          <div className="flex items-center justify-between text-slate-500 dark:text-slate-400 text-xs font-mono uppercase tracking-wider">
            <span>High / Critical Alerts</span>
            <AlertTriangle className="w-4 h-4 text-orange-500" />
          </div>
          <div className="mt-3 flex items-baseline space-x-2">
            <span className="text-2xl font-bold font-mono text-slate-900 dark:text-slate-100">
              {metrics ? metrics.high_critical_count : '—'}
            </span>
          </div>
          <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
            Requires active containment
          </p>
        </div>

        <div className="p-5 rounded-xl border border-slate-200 dark:border-cyber-border bg-white dark:bg-cyber-surface">
          <div className="flex items-center justify-between text-slate-500 dark:text-slate-400 text-xs font-mono uppercase tracking-wider">
            <span>Active Knowledge Base</span>
            <ShieldCheck className="w-4 h-4 text-emerald-500" />
          </div>
          <div className="mt-3 flex items-baseline space-x-2">
            <span className="text-2xl font-bold font-mono text-slate-900 dark:text-slate-100">
              {metrics ? metrics.rules_active_count : '49'}
            </span>
            <span className="text-xs text-slate-400 font-mono">Rules</span>
          </div>
          <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
            {metrics ? `${metrics.threat_library_count} threat catalog profiles` : 'Deterministic rule set'}
          </p>
        </div>
      </div>

      {/* Main Content Grid: Recent Diagnoses & Risk Visualization */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Recent Diagnoses List (2 cols) */}
        <div className="lg:col-span-2 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100">
                Recent Security Diagnoses
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Real-time evaluations from structured forms, conversational chat, and simulations
              </p>
            </div>
            <button
              onClick={() => onNavigate('history')}
              className="text-xs text-emerald-600 dark:text-emerald-400 hover:underline font-medium inline-flex items-center"
            >
              <span>View full history</span>
              <ChevronRight className="w-3.5 h-3.5 ml-0.5" />
            </button>
          </div>

          <div className="rounded-xl border border-slate-200 dark:border-cyber-border bg-white dark:bg-cyber-surface overflow-hidden">
            {metrics && metrics.recent_diagnoses.length > 0 ? (
              <div className="divide-y divide-slate-100 dark:divide-cyber-border">
                {metrics.recent_diagnoses.map((inc) => (
                  <div
                    key={inc.id}
                    onClick={() => onNavigate('history', inc.id)}
                    className="p-4 sm:px-6 hover:bg-slate-50 dark:hover:bg-cyber-elevated/60 transition-colors cursor-pointer flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                  >
                    <div className="space-y-1">
                      <div className="flex items-center space-x-2.5">
                        <span className="font-semibold text-sm text-slate-900 dark:text-slate-100">
                          {inc.primary_threat}
                        </span>
                        <Badge variant="severity" severity={inc.severity} size="sm" />
                      </div>
                      <p className="text-xs text-slate-500 dark:text-slate-400 line-clamp-1">
                        {inc.summary}
                      </p>
                    </div>

                    <div className="flex items-center space-x-4 shrink-0 text-xs">
                      <div className="text-right">
                        <div className="font-mono text-slate-700 dark:text-slate-300 font-medium">
                          Score {inc.risk_score}
                        </div>
                        <div className="text-slate-400 font-mono text-[11px]">
                          {inc.confidence_label} ({Math.round(inc.confidence * 100)}%)
                        </div>
                      </div>
                      <ArrowRight className="w-4 h-4 text-slate-400" />
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="p-8 text-center space-y-3">
                <div className="w-10 h-10 rounded-full bg-slate-100 dark:bg-cyber-elevated text-slate-400 mx-auto flex items-center justify-center">
                  <ShieldCheck className="w-5 h-5" />
                </div>
                <h4 className="text-sm font-semibold text-slate-800 dark:text-slate-200">
                  No Security Incidents Yet
                </h4>
                <p className="text-xs text-slate-500 dark:text-slate-400 max-w-sm mx-auto">
                  Submit observations through the Analyze Incident form or Chat Diagnosis to trigger expert-system reasoning.
                </p>
                <div className="pt-2 flex justify-center gap-3">
                  <button
                    onClick={() => onNavigate('analyze')}
                    className="px-3 py-1.5 text-xs font-medium rounded-lg bg-emerald-600 text-white hover:bg-emerald-500 transition-colors"
                  >
                    Run First Analysis
                  </button>
                  <button
                    onClick={() => onNavigate('scenarios')}
                    className="px-3 py-1.5 text-xs font-medium rounded-lg border border-slate-200 dark:border-cyber-border text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-cyber-elevated transition-colors"
                  >
                    Try Simulated Scenarios
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Risk Visualization / Quick Tools (1 col) */}
        <div className="space-y-4">
          <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100">
            Current Risk Posture
          </h3>

          {metrics ? (
            <RiskMeter
              riskScore={{
                score: metrics.overall_risk_score,
                level: metrics.overall_risk_level,
                description:
                  metrics.overall_risk_score > 50
                    ? 'Elevated risk posture detected across recently monitored security incidents.'
                    : 'System posture is currently stable. Maintain standard defensive controls.',
                contributing_factors: [
                  `${metrics.incidents_analyzed} total security evaluations completed`,
                  `${metrics.high_critical_count} high-severity incidents flagged`,
                  '49 deterministic rules continuously monitoring facts'
                ],
                category_breakdowns: [],
                urgent_actions: [
                  'Review unmitigated high-severity incidents',
                  'Perform credential resets where account takeover is suspected'
                ]
              }}
            />
          ) : (
            <div className="p-6 rounded-xl border border-slate-200 dark:border-cyber-border bg-white dark:bg-cyber-surface animate-pulse h-48" />
          )}

          {/* Quick Shortcuts */}
          <div className="rounded-xl border border-slate-200 dark:border-cyber-border bg-white dark:bg-cyber-surface p-5 space-y-3">
            <div className="text-xs font-mono uppercase tracking-wider text-slate-400">
              Quick Security Actions
            </div>
            <div className="space-y-2">
              <button
                onClick={() => onNavigate('scenarios')}
                className="w-full text-left p-2.5 rounded-lg border border-slate-200/60 dark:border-cyber-border/60 hover:border-emerald-500/50 hover:bg-slate-50 dark:hover:bg-cyber-elevated text-xs transition-all flex items-center justify-between"
              >
                <div>
                  <div className="font-medium text-slate-800 dark:text-slate-200">Test Attack Scenarios</div>
                  <div className="text-slate-500 dark:text-slate-400 text-[11px]">Run simulated ransomware or ATO telemetry</div>
                </div>
                <ChevronRight className="w-3.5 h-3.5 text-slate-400" />
              </button>

              <button
                onClick={() => onNavigate('password')}
                className="w-full text-left p-2.5 rounded-lg border border-slate-200/60 dark:border-cyber-border/60 hover:border-emerald-500/50 hover:bg-slate-50 dark:hover:bg-cyber-elevated text-xs transition-all flex items-center justify-between"
              >
                <div>
                  <div className="font-medium text-slate-800 dark:text-slate-200">Secure Password Generator</div>
                  <div className="text-slate-500 dark:text-slate-400 text-[11px]">Cryptographic randomness with zero storage</div>
                </div>
                <ChevronRight className="w-3.5 h-3.5 text-slate-400" />
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

function ChevronRight({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="9 18 15 12 9 6" />
    </svg>
  );
}
