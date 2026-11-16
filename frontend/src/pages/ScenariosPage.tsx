import React, { useState, useEffect } from 'react';
import {
  FlaskConical,
  Play,
  CheckCircle2,
  ShieldAlert,
  ArrowRight,
  Terminal,
  RotateCcw,
  BookOpen
} from 'lucide-react';
import { api } from '../services/api';
import { AttackScenario, DiagnosisReport } from '../types';
import { Badge } from '../components/common/Badge';
import { Modal } from '../components/common/Modal';

export const ScenariosPage: React.FC = () => {
  const [scenarios, setScenarios] = useState<AttackScenario[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeScenario, setActiveScenario] = useState<AttackScenario | null>(null);
  const [report, setReport] = useState<DiagnosisReport | null>(null);
  const [running, setRunning] = useState(false);

  useEffect(() => {
    async function loadScenarios() {
      try {
        const data = await api.getScenarios();
        setScenarios(data);
      } catch (err) {
        console.error('Failed to load scenarios:', err);
      } finally {
        setLoading(false);
      }
    }
    loadScenarios();
  }, []);

  const handleRunScenario = async (scen: AttackScenario) => {
    setActiveScenario(scen);
    setReport(null);
    setRunning(true);
    try {
      const res = await api.runScenario(scen.id);
      setReport(res);
    } catch (err: any) {
      console.error(err);
      alert('Failed to evaluate scenario: ' + (err.message || 'Error'));
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <div className="inline-flex items-center space-x-2 px-2.5 py-0.5 rounded-full bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20 text-xs font-mono mb-2">
          <span>Safe Educational Module</span>
        </div>
        <h2 className="text-xl font-bold tracking-tight text-slate-900 dark:text-white">
          Simulated Attack Scenarios
        </h2>
        <p className="text-sm text-slate-600 dark:text-slate-300 mt-1">
          Review realistic, sanitized incident evidence logs and execute CyberMate's deterministic expert engine against each case to observe reasoning and defense recommendations.
        </p>
      </div>

      {/* Scenarios Grid */}
      {loading ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {[1, 2, 3, 4, 5, 6].map((n) => (
            <div key={n} className="h-56 rounded-xl bg-slate-100 dark:bg-cyber-surface animate-pulse" />
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {scenarios.map((scen) => (
            <div
              key={scen.id}
              className="rounded-xl border border-slate-200 dark:border-cyber-border bg-white dark:bg-cyber-surface p-5 flex flex-col justify-between hover:border-emerald-500/30 transition-all shadow-sm"
            >
              <div className="space-y-3">
                <div className="flex items-center justify-between text-xs">
                  <Badge variant="category" size="sm">
                    {scen.category}
                  </Badge>
                  <span className="text-slate-500 font-mono text-[11px]">
                    {scen.difficulty}
                  </span>
                </div>

                <h3 className="font-semibold text-slate-900 dark:text-slate-100 text-sm sm:text-base leading-snug">
                  {scen.title}
                </h3>

                <p className="text-xs text-slate-500 dark:text-slate-400 line-clamp-2 leading-relaxed">
                  {scen.description}
                </p>

                {/* Evidence count snippet */}
                <div className="pt-2">
                  <span className="text-[11px] font-mono text-slate-400 block mb-1">
                    Simulated Telemetry:
                  </span>
                  <div className="p-2 rounded bg-slate-50 dark:bg-cyber-elevated text-[11px] font-mono text-slate-600 dark:text-slate-300 truncate">
                    {scen.simulated_evidence[0]}
                  </div>
                </div>
              </div>

              <div className="pt-4 mt-4 border-t border-slate-100 dark:border-cyber-border flex items-center justify-between">
                <span className="text-xs text-slate-400 font-mono">
                  Target: {scen.expected_threat}
                </span>

                <button
                  onClick={() => handleRunScenario(scen)}
                  className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 text-white shadow-sm transition-all"
                >
                  <Play className="w-3 h-3 fill-current" />
                  <span>Diagnose</span>
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Scenario Execution Modal */}
      {activeScenario && (
        <Modal
          isOpen={Boolean(activeScenario)}
          onClose={() => setActiveScenario(null)}
          title={activeScenario.title}
          subtitle={`Educational Scenario • ${activeScenario.category} Simulation`}
          maxWidth="2xl"
        >
          <div className="space-y-6 text-sm">
            {/* Story / Context */}
            <div className="space-y-2">
              <h4 className="text-xs font-mono uppercase tracking-wider text-slate-400">
                Incident Context & Timeline
              </h4>
              <p className="text-xs sm:text-sm text-slate-700 dark:text-slate-300 leading-relaxed bg-slate-50 dark:bg-cyber-elevated p-3.5 rounded-lg border border-slate-200/60 dark:border-cyber-border/60">
                {activeScenario.background_story}
              </p>
            </div>

            {/* Simulated Evidence Logs */}
            <div className="space-y-2">
              <h4 className="text-xs font-mono uppercase tracking-wider text-slate-400">
                Simulated Event Telemetry
              </h4>
              <div className="space-y-1.5 bg-slate-900 text-slate-200 p-3.5 rounded-lg font-mono text-xs border border-slate-800">
                {activeScenario.simulated_evidence.map((ev, i) => (
                  <div key={i} className="flex items-start space-x-2">
                    <span className="text-emerald-400 select-none">›</span>
                    <span>{ev}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Diagnostic Result */}
            {running ? (
              <div className="p-8 text-center space-y-2">
                <div className="w-6 h-6 border-2 border-emerald-500 border-t-transparent rounded-full animate-spin mx-auto" />
                <p className="text-xs font-mono text-slate-500">
                  Executing 49 deterministic rules against scenario facts...
                </p>
              </div>
            ) : report ? (
              <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/5 dark:bg-emerald-950/20 p-5 space-y-4">
                <div className="flex items-start justify-between">
                  <div>
                    <div className="text-[11px] font-mono text-emerald-600 dark:text-emerald-400 uppercase tracking-wider">
                      Diagnosis Result
                    </div>
                    <h4 className="text-base font-bold text-slate-900 dark:text-slate-100 mt-0.5">
                      {report.primary_threat?.threat}
                    </h4>
                  </div>
                  {report.primary_threat && (
                    <Badge variant="severity" severity={report.primary_threat.severity} />
                  )}
                </div>

                <div className="text-xs text-slate-600 dark:text-slate-300 space-y-1.5">
                  <div className="font-mono text-slate-400 text-[11px] uppercase tracking-wider">
                    Evidence Verified by Rule Engine:
                  </div>
                  {report.primary_threat?.evidence.map((e, idx) => (
                    <div key={idx} className="flex items-center space-x-2 text-slate-700 dark:text-slate-300">
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500" />
                      <span>{e}</span>
                    </div>
                  ))}
                </div>

                <div className="pt-2 border-t border-emerald-500/20 space-y-1">
                  <div className="font-mono text-slate-400 text-[11px] uppercase tracking-wider">
                    Recommended Defensive Actions:
                  </div>
                  <ol className="text-xs space-y-1 text-slate-700 dark:text-slate-300">
                    {report.overall_recommendations.slice(0, 3).map((r, idx) => (
                      <li key={idx} className="flex items-start space-x-2">
                        <span className="font-bold text-emerald-600 dark:text-emerald-400">{idx + 1}.</span>
                        <span>{r}</span>
                      </li>
                    ))}
                  </ol>
                </div>

                {/* Educational Takeaway */}
                <div className="pt-3 border-t border-emerald-500/20 text-xs">
                  <span className="font-mono text-emerald-600 dark:text-emerald-400 uppercase tracking-wider block mb-1">
                    Defensive Takeaway:
                  </span>
                  <p className="text-slate-600 dark:text-slate-300 italic">
                    {activeScenario.educational_takeaway}
                  </p>
                </div>
              </div>
            ) : null}
          </div>
        </Modal>
      )}
    </div>
  );
};
