import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  Terminal,
  Cpu,
  Layers,
  ArrowRight,
  Database,
  Lock,
  Workflow,
  Sparkles,
  ChevronDown,
  ChevronUp
} from 'lucide-react';
import { api } from '../services/api';
import { RuleDefinition } from '../types';
import { Badge } from '../components/common/Badge';

export const AboutPage: React.FC = () => {
  const [rules, setRules] = useState<RuleDefinition[]>([]);
  const [loadingRules, setLoadingRules] = useState(false);
  const [showRules, setShowRules] = useState(false);

  useEffect(() => {
    async function loadActiveRules() {
      setLoadingRules(true);
      try {
        const data = await api.getActiveRules();
        setRules(data);
      } catch (err) {
        console.error('Failed to load rules:', err);
      } finally {
        setLoadingRules(false);
      }
    }
    if (showRules && rules.length === 0) {
      loadActiveRules();
    }
  }, [showRules, rules.length]);

  return (
    <div className="space-y-8 max-w-4xl mx-auto">
      {/* Header */}
      <div>
        <div className="inline-flex items-center space-x-2 px-2.5 py-0.5 rounded-full bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20 text-xs font-mono mb-2">
          <span>System Architecture & Principles</span>
        </div>
        <h2 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white">
          About CyberMate
        </h2>
        <p className="text-sm text-slate-600 dark:text-slate-300 mt-1 leading-relaxed">
          CyberMate is a defensive Cybersecurity Threat Detection & Diagnosis Expert System powered by deterministic rule evaluation, transparent evidence tracing, and structured defensive knowledge.
        </p>
      </div>

      {/* Core Concept: Deterministic Reasoning vs LLM Blackbox */}
      <div className="rounded-xl border border-slate-200 dark:border-cyber-border bg-white dark:bg-cyber-surface p-6 shadow-sm space-y-4">
        <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100 flex items-center space-x-2">
          <Terminal className="w-4 h-4 text-emerald-500" />
          <span>Core Engineering Principle: The Expert System Makes The Decision</span>
        </h3>
        <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-300 leading-relaxed">
          Unlike generic generative AI chatbots that guess outcomes through statistical token probability, <strong>CyberMate's threat classification is strictly governed by a deterministic inference engine</strong>. Every conclusion is directly traceable to observed security facts and declarative defensive rules.
        </p>
        <div className="p-4 rounded-lg bg-slate-50 dark:bg-cyber-elevated/40 border border-slate-200/60 dark:border-cyber-border/60 text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
          <span className="font-semibold text-slate-900 dark:text-slate-100 block mb-1">
            Optional LLM Architecture
          </span>
          Large language models (such as Gemini) are intentionally isolated to natural language interpretation and explanation generation. They do <em>not</em> have unilateral authority to classify security threats or bypass expert rules.
        </div>
      </div>

      {/* Inference Pipeline Diagram */}
      <div className="rounded-xl border border-slate-200 dark:border-cyber-border bg-white dark:bg-cyber-surface p-6 shadow-sm space-y-4">
        <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100 flex items-center space-x-2">
          <Workflow className="w-4 h-4 text-emerald-500" />
          <span>How CyberMate Works — The Diagnostic Pipeline</span>
        </h3>

        {/* ASCII / Visual Flow */}
        <div className="grid grid-cols-1 sm:grid-cols-7 gap-2 text-center text-xs font-mono pt-2">
          <div className="p-3 rounded-lg bg-slate-50 dark:bg-cyber-elevated border border-slate-200 dark:border-cyber-border">
            <span className="text-slate-400 text-[10px] block">Step 1</span>
            <span className="font-semibold text-slate-800 dark:text-slate-200">Observations</span>
          </div>

          <div className="flex items-center justify-center text-slate-400">
            <span className="hidden sm:inline">→</span>
            <span className="sm:hidden">↓</span>
          </div>

          <div className="p-3 rounded-lg bg-slate-50 dark:bg-cyber-elevated border border-slate-200 dark:border-cyber-border">
            <span className="text-slate-400 text-[10px] block">Step 2</span>
            <span className="font-semibold text-slate-800 dark:text-slate-200">Structured Facts</span>
          </div>

          <div className="flex items-center justify-center text-slate-400">
            <span className="hidden sm:inline">→</span>
            <span className="sm:hidden">↓</span>
          </div>

          <div className="p-3 rounded-lg bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20 font-bold">
            <span className="text-[10px] block">Step 3</span>
            <span>49-Rule Engine</span>
          </div>

          <div className="flex items-center justify-center text-slate-400">
            <span className="hidden sm:inline">→</span>
            <span className="sm:hidden">↓</span>
          </div>

          <div className="p-3 rounded-lg bg-slate-50 dark:bg-cyber-elevated border border-slate-200 dark:border-cyber-border">
            <span className="text-slate-400 text-[10px] block">Step 4</span>
            <span className="font-semibold text-slate-800 dark:text-slate-200">Threat & Actions</span>
          </div>
        </div>

        <ul className="space-y-2 text-xs text-slate-600 dark:text-slate-300 pt-2">
          <li className="flex items-start space-x-2">
            <span className="text-emerald-500 font-bold">1.</span>
            <span><strong>Observations:</strong> Telemetry from authentication portals, network flows, endpoints, cloud APIs, and email logs.</span>
          </li>
          <li className="flex items-start space-x-2">
            <span className="text-emerald-500 font-bold">2.</span>
            <span><strong>Facts:</strong> Normalization into verified boolean flags and numerical thresholds (e.g. failed_login_count &gt;= 10).</span>
          </li>
          <li className="flex items-start space-x-2">
            <span className="text-emerald-500 font-bold">3.</span>
            <span><strong>Rule Inference:</strong> Declarative forward-chaining matching conditions, calculating confidence, and weighting severity.</span>
          </li>
          <li className="flex items-start space-x-2">
            <span className="text-emerald-500 font-bold">4.</span>
            <span><strong>Diagnosis & Roadmap:</strong> Primary threat, related threats, evidence reasoning, risk score (0-100), and prescriptive mitigations.</span>
          </li>
        </ul>
      </div>

      {/* Operational Disclaimer */}
      <div className="rounded-xl border border-amber-500/20 bg-amber-500/5 dark:bg-amber-950/20 p-5 space-y-2 text-xs text-amber-900 dark:text-amber-200">
        <div className="font-semibold flex items-center space-x-1.5">
          <ShieldAlert className="w-4 h-4 text-amber-500 shrink-0" />
          <span>Defensive Defensive Operations & Limitations Notice</span>
        </div>
        <p className="leading-relaxed">
          CyberMate is engineered strictly for educational, triage, and defensive diagnosis purposes. It is not an offensive exploitation or penetration tool. It does not replace 24/7 human Security Operations Center (SOC) oversight, deep forensic memory carving, or dedicated managed detection and response (MDR) services.
        </p>
      </div>

      {/* Expandable Active Rules Viewer (Inspect 49 Rules) */}
      <div className="rounded-xl border border-slate-200 dark:border-cyber-border bg-white dark:bg-cyber-surface p-6 shadow-sm space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100">
              Active Rule Engine Catalog
            </h3>
            <p className="text-xs text-slate-500 mt-0.5">
              49 declarative diagnostic rules loaded in memory
            </p>
          </div>
          <button
            onClick={() => setShowRules(!showRules)}
            className="inline-flex items-center space-x-1 px-3 py-1.5 rounded-lg text-xs font-medium border border-slate-200 dark:border-cyber-border hover:bg-slate-50 dark:hover:bg-cyber-elevated text-slate-700 dark:text-slate-300 transition-colors"
          >
            <span>{showRules ? 'Collapse Rules' : 'Inspect All 49 Rules'}</span>
            {showRules ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          </button>
        </div>

        {showRules && (
          <div className="space-y-3 pt-3 border-t border-slate-100 dark:border-cyber-border">
            {loadingRules ? (
              <div className="py-6 text-center text-xs text-slate-500 font-mono">
                Loading rule catalog...
              </div>
            ) : (
              <div className="space-y-2 max-h-96 overflow-y-auto pr-1">
                {rules.map((rule) => (
                  <div
                    key={rule.id}
                    className="p-3 rounded-lg bg-slate-50 dark:bg-cyber-elevated/40 border border-slate-200/60 dark:border-cyber-border/60 text-xs space-y-1.5"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <span className="font-mono font-bold text-emerald-600 dark:text-emerald-400">
                          {rule.id}
                        </span>
                        <span className="font-medium text-slate-900 dark:text-slate-100">
                          {rule.name}
                        </span>
                      </div>
                      <Badge variant="severity" severity={rule.severity} size="sm" />
                    </div>
                    <div className="text-slate-500 dark:text-slate-400 flex flex-wrap gap-x-3 text-[11px] font-mono">
                      <span>Threat: {rule.threat}</span>
                      <span>Category: {rule.category}</span>
                      {rule.mitre_technique && <span>MITRE: {rule.mitre_technique}</span>}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Future Roadmap & Architecture Note */}
      <div className="rounded-xl border border-slate-200 dark:border-cyber-border bg-white dark:bg-cyber-surface p-6 shadow-sm space-y-4">
        <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100 flex items-center space-x-2">
          <Database className="w-4 h-4 text-emerald-500" />
          <span>Architectural Roadmap & Enterprise Extensions</span>
        </h3>
        <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-300 leading-relaxed">
          CyberMate's backend is modularly structured to support seamless enterprise migration:
        </p>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs pt-1">
          <div className="p-3 rounded-lg bg-slate-50 dark:bg-cyber-elevated/40 border border-slate-200/60 dark:border-cyber-border/60 space-y-1">
            <span className="font-semibold text-slate-800 dark:text-slate-200 block">
              Identity & Authentication
            </span>
            <p className="text-slate-500 dark:text-slate-400">
              Authentication and personalized security history can be added in a future version via OAuth2 / OIDC providers (Okta, Entra ID).
            </p>
          </div>

          <div className="p-3 rounded-lg bg-slate-50 dark:bg-cyber-elevated/40 border border-slate-200/60 dark:border-cyber-border/60 space-y-1">
            <span className="font-semibold text-slate-800 dark:text-slate-200 block">
              PostgreSQL & Time-Series DB
            </span>
            <p className="text-slate-500 dark:text-slate-400">
              Database layer is built on SQLAlchemy declarative models, ready to switch from SQLite to PostgreSQL by configuring DATABASE_URL.
            </p>
          </div>

          <div className="p-3 rounded-lg bg-slate-50 dark:bg-cyber-elevated/40 border border-slate-200/60 dark:border-cyber-border/60 space-y-1">
            <span className="font-semibold text-slate-800 dark:text-slate-200 block">
              SIEM & Syslog Ingestion
            </span>
            <p className="text-slate-500 dark:text-slate-400">
              Future webhook endpoints for automated parsing of Splunk, Elastic, and Microsoft Sentinel CEF/LEEF event streams.
            </p>
          </div>

          <div className="p-3 rounded-lg bg-slate-50 dark:bg-cyber-elevated/40 border border-slate-200/60 dark:border-cyber-border/60 space-y-1">
            <span className="font-semibold text-slate-800 dark:text-slate-200 block">
              Dynamic Rule Packs
            </span>
            <p className="text-slate-500 dark:text-slate-400">
              Hot-reloadable Sigma and YARA rule pack converters translating external threat intelligence into deterministic facts.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
