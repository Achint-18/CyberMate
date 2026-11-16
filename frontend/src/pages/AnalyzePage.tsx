import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  RotateCcw,
  Sparkles,
  ArrowRight,
  Info,
  ExternalLink,
  ChevronDown,
  Layers,
  Save
} from 'lucide-react';
import { api } from '../services/api';
import { IndicatorMetadata, DiagnosisReport, ThreatDiagnosis } from '../types';
import { Badge } from '../components/common/Badge';
import { RiskMeter } from '../components/common/RiskMeter';

export const AnalyzePage: React.FC = () => {
  const [indicators, setIndicators] = useState<IndicatorMetadata[]>([]);
  const [loadingIndicators, setLoadingIndicators] = useState(true);
  const [selectedCategory, setSelectedCategory] = useState<string>('All');
  const [incidentTitle, setIncidentTitle] = useState('Incident Observation');

  // Facts state
  const [facts, setFacts] = useState<Record<string, any>>({
    failed_login_count: 0
  });

  // Analysis result
  const [report, setReport] = useState<DiagnosisReport | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);

  useEffect(() => {
    async function loadIndicators() {
      try {
        const data = await api.getIndicators();
        setIndicators(data);
      } catch (err) {
        console.error('Failed to load indicators:', err);
      } finally {
        setLoadingIndicators(false);
      }
    }
    loadIndicators();
  }, []);

  const categories = ['All', 'Authentication', 'Network', 'System', 'Endpoint', 'Account', 'Application', 'Email', 'Cloud', 'Insider'];

  const filteredIndicators = indicators.filter(
    (i) => selectedCategory === 'All' || i.category.toLowerCase() === selectedCategory.toLowerCase()
  );

  const activeIndicatorCount = Object.keys(facts).filter((k) => {
    const val = facts[k];
    if (typeof val === 'boolean') return val;
    if (typeof val === 'number') return val > 0;
    return Boolean(val);
  }).length;

  const handleToggle = (id: string) => {
    setFacts((prev) => ({
      ...prev,
      [id]: !prev[id]
    }));
  };

  const handleNumberChange = (id: string, value: number) => {
    setFacts((prev) => ({
      ...prev,
      [id]: Math.max(0, value)
    }));
  };

  const handleReset = () => {
    setFacts({ failed_login_count: 0 });
    setReport(null);
    setSaveSuccess(false);
  };

  const handleRunAnalysis = async () => {
    setIsAnalyzing(true);
    setSaveSuccess(false);
    try {
      const result = await api.analyzeIncident(facts, incidentTitle, 'structured', true);
      setReport(result);
      setSaveSuccess(true);
    } catch (err: any) {
      console.error('Analysis failed:', err);
      alert('Analysis error: ' + (err.message || 'Unknown error'));
    } finally {
      setIsAnalyzing(false);
    }
  };

  return (
    <div className="space-y-8">
      {/* Intro Header */}
      <div>
        <h2 className="text-xl font-bold tracking-tight text-slate-900 dark:text-white">
          Security Incident Analysis
        </h2>
        <p className="text-sm text-slate-600 dark:text-slate-300 mt-1">
          Select observed indicators across authentication, network, endpoint, or system layers. CyberMate will evaluate the facts against the deterministic rule engine.
        </p>
      </div>

      {/* Main Grid: Left = Indicator Form, Right = Real-time Diagnosis Result */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Left Column: Indicators Selector (7 cols) */}
        <div className="lg:col-span-7 space-y-6">
          <div className="rounded-xl border border-slate-200 dark:border-cyber-border bg-white dark:bg-cyber-surface p-5 sm:p-6 shadow-sm space-y-5">
            {/* Title & Metadata input */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-100 dark:border-cyber-border">
              <div className="flex-1">
                <label className="block text-xs font-mono uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-1">
                  Incident Title / Reference
                </label>
                <input
                  type="text"
                  value={incidentTitle}
                  onChange={(e) => setIncidentTitle(e.target.value)}
                  placeholder="e.g. Anomalous Sign-in on Finance Host"
                  className="w-full px-3 py-2 text-sm rounded-lg bg-slate-50 dark:bg-cyber-elevated border border-slate-200 dark:border-cyber-border text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-emerald-500"
                />
              </div>

              <div className="flex items-center space-x-2 pt-4 sm:pt-0">
                <button
                  onClick={handleReset}
                  type="button"
                  className="inline-flex items-center space-x-1.5 px-3 py-2 text-xs font-medium rounded-lg border border-slate-200 dark:border-cyber-border text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100 hover:bg-slate-50 dark:hover:bg-cyber-elevated transition-colors"
                >
                  <RotateCcw className="w-3.5 h-3.5" />
                  <span>Reset</span>
                </button>
              </div>
            </div>

            {/* Category Filter Pills */}
            <div className="space-y-2">
              <label className="block text-xs font-mono uppercase tracking-wider text-slate-500 dark:text-slate-400">
                Filter Indicators by Domain
              </label>
              <div className="flex flex-wrap gap-1.5">
                {categories.map((cat) => (
                  <button
                    key={cat}
                    onClick={() => setSelectedCategory(cat)}
                    className={`px-2.5 py-1 text-xs rounded-md font-medium transition-all ${
                      selectedCategory === cat
                        ? 'bg-slate-900 text-white dark:bg-emerald-500/20 dark:text-emerald-400 dark:border dark:border-emerald-500/30'
                        : 'bg-slate-100 dark:bg-cyber-elevated text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                    }`}
                  >
                    {cat}
                  </button>
                ))}
              </div>
            </div>

            {/* Indicator List */}
            <div className="space-y-3 pt-2">
              <div className="flex items-center justify-between text-xs font-mono text-slate-500 dark:text-slate-400">
                <span>{filteredIndicators.length} Available Indicators</span>
                <span className="text-emerald-600 dark:text-emerald-400 font-semibold">
                  {activeIndicatorCount} Selected
                </span>
              </div>

              {loadingIndicators ? (
                <div className="space-y-2 py-4">
                  {[1, 2, 3, 4, 5].map((n) => (
                    <div key={n} className="h-14 bg-slate-100 dark:bg-cyber-elevated rounded-lg animate-pulse" />
                  ))}
                </div>
              ) : (
                <div className="space-y-2.5 max-h-[560px] overflow-y-auto pr-1">
                  {filteredIndicators.map((ind) => {
                    const isChecked = Boolean(facts[ind.id]);
                    return (
                      <div
                        key={ind.id}
                        className={`p-3.5 rounded-lg border transition-all ${
                          isChecked
                            ? 'bg-emerald-500/5 dark:bg-emerald-950/20 border-emerald-500/30'
                            : 'bg-slate-50/60 dark:bg-cyber-elevated/40 border-slate-200/70 dark:border-cyber-border/70 hover:border-slate-300 dark:hover:border-cyber-border'
                        }`}
                      >
                        <div className="flex items-start justify-between gap-3">
                          <div className="space-y-1 flex-1">
                            <div className="flex items-center space-x-2">
                              <span className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                                {ind.name}
                              </span>
                              <Badge variant="category" size="sm">
                                {ind.category}
                              </Badge>
                            </div>
                            <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
                              {ind.description}
                            </p>
                          </div>

                          {/* Control */}
                          <div className="shrink-0 pt-0.5">
                            {ind.data_type === 'number' ? (
                              <div className="flex items-center space-x-2">
                                <label className="text-[11px] font-mono text-slate-400">Attempts:</label>
                                <input
                                  type="number"
                                  min="0"
                                  max="999"
                                  value={facts[ind.id] || 0}
                                  onChange={(e) => handleNumberChange(ind.id, parseInt(e.target.value) || 0)}
                                  className="w-16 px-2 py-1 text-xs text-center font-mono rounded bg-white dark:bg-cyber-surface border border-slate-300 dark:border-cyber-border text-slate-900 dark:text-slate-100 focus:ring-1 focus:ring-emerald-500"
                                />
                              </div>
                            ) : (
                              <button
                                type="button"
                                onClick={() => handleToggle(ind.id)}
                                className={`w-10 h-6 flex items-center rounded-full p-1 transition-colors duration-200 ease-in-out focus:outline-none ${
                                  isChecked ? 'bg-emerald-600' : 'bg-slate-300 dark:bg-cyber-subtle'
                                }`}
                                aria-label={`Toggle ${ind.name}`}
                              >
                                <div
                                  className={`bg-white w-4 h-4 rounded-full shadow-md transform transition-transform duration-200 ease-in-out ${
                                    isChecked ? 'translate-x-4' : 'translate-x-0'
                                  }`}
                                />
                              </button>
                            )}
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Run Analysis Action Button */}
            <div className="pt-4 border-t border-slate-100 dark:border-cyber-border flex items-center justify-between">
              <div className="text-xs text-slate-500 font-mono">
                {activeIndicatorCount === 0 ? 'Select at least 1 indicator' : `${activeIndicatorCount} observation(s) active`}
              </div>
              <button
                type="button"
                onClick={handleRunAnalysis}
                disabled={isAnalyzing}
                className="inline-flex items-center space-x-2 px-5 py-2.5 rounded-lg text-sm font-semibold bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white shadow-sm transition-all focus:ring-2 focus:ring-emerald-500"
              >
                {isAnalyzing ? (
                  <>
                    <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                    <span>Evaluating Rules...</span>
                  </>
                ) : (
                  <>
                    <ShieldAlert className="w-4 h-4" />
                    <span>Run Expert Analysis</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>

        {/* Right Column: Expert System Diagnosis Result (5 cols) */}
        <div className="lg:col-span-5 space-y-6">
          {report ? (
            <div className="space-y-6 animate-in fade-in slide-in-from-bottom-2 duration-300">
              {/* Primary Threat Card */}
              <div className="rounded-xl border border-slate-200 dark:border-cyber-border bg-white dark:bg-cyber-surface p-6 shadow-sm space-y-4">
                <div className="flex items-start justify-between">
                  <div>
                    <div className="text-xs font-mono uppercase tracking-wider text-slate-500 dark:text-slate-400 flex items-center space-x-1.5">
                      <span className="w-2 h-2 rounded-full bg-emerald-500" />
                      <span>Expert System Diagnosis</span>
                    </div>
                    <h3 className="text-xl font-bold text-slate-900 dark:text-slate-100 mt-1">
                      {report.primary_threat ? report.primary_threat.threat : 'No Active Threat Detected'}
                    </h3>
                  </div>

                  {report.primary_threat && (
                    <Badge variant="severity" severity={report.primary_threat.severity} />
                  )}
                </div>

                {report.primary_threat ? (
                  <>
                    {/* Confidence & MITRE */}
                    <div className="flex flex-wrap items-center gap-3 py-2 border-y border-slate-100 dark:border-cyber-border text-xs">
                      <div className="flex items-center space-x-1.5">
                        <span className="text-slate-500 dark:text-slate-400">Confidence:</span>
                        <span className="font-mono font-semibold text-emerald-600 dark:text-emerald-400">
                          {Math.round(report.primary_threat.confidence * 100)}%
                        </span>
                        <span className="text-slate-400">({report.primary_threat.confidence_label})</span>
                      </div>
                      {report.primary_threat.mitre_technique && (
                        <div className="flex items-center space-x-1 text-slate-600 dark:text-slate-400 font-mono text-[11px] bg-slate-100 dark:bg-cyber-elevated px-2 py-0.5 rounded">
                          <span>MITRE {report.primary_threat.mitre_technique}</span>
                        </div>
                      )}
                    </div>

                    {/* Transparent reasoning */}
                    <div className="space-y-2">
                      <div className="text-xs uppercase font-mono tracking-wider text-slate-500 dark:text-slate-400">
                        Why CyberMate reached this conclusion
                      </div>
                      <div className="space-y-1.5">
                        {report.primary_threat.evidence.map((ev, i) => (
                          <div key={i} className="flex items-start space-x-2 text-xs text-slate-700 dark:text-slate-300">
                            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500 shrink-0 mt-0.5" />
                            <span>{ev}</span>
                          </div>
                        ))}
                      </div>
                      <p className="text-xs text-slate-600 dark:text-slate-400 pt-1 leading-relaxed">
                        {report.primary_threat.explanation.split('\n\n')[0]}
                      </p>
                    </div>

                    {/* Prescriptive Recommended Actions */}
                    <div className="space-y-2 pt-2 border-t border-slate-100 dark:border-cyber-border">
                      <div className="text-xs uppercase font-mono tracking-wider text-slate-500 dark:text-slate-400">
                        Recommended Defensive Actions
                      </div>
                      <ol className="space-y-2 text-xs text-slate-700 dark:text-slate-300">
                        {report.overall_recommendations.map((rec, i) => (
                          <li key={i} className="flex items-start space-x-2">
                            <span className="w-4 h-4 rounded-full bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 font-mono text-[10px] flex items-center justify-center shrink-0 mt-0.5 font-bold">
                              {i + 1}
                            </span>
                            <span>{rec}</span>
                          </li>
                        ))}
                      </ol>
                    </div>
                  </>
                ) : (
                  <div className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed py-2">
                    {report.summary}
                  </div>
                )}

                {/* Audit & Metadata footer */}
                <div className="pt-3 border-t border-slate-100 dark:border-cyber-border flex items-center justify-between text-[11px] font-mono text-slate-400">
                  <span>{report.evaluation_metadata.rules_evaluated} rules evaluated</span>
                  <span>{report.evaluation_metadata.inference_time_ms} ms</span>
                  {saveSuccess && (
                    <span className="text-emerald-500 flex items-center gap-1">
                      <Save className="w-3 h-3" /> Saved to History
                    </span>
                  )}
                </div>
              </div>

              {/* Related Threats (Multiple possible diagnoses) */}
              {report.related_threats.length > 0 && (
                <div className="rounded-xl border border-slate-200 dark:border-cyber-border bg-white dark:bg-cyber-surface p-5 shadow-sm space-y-3">
                  <div className="text-xs font-mono uppercase tracking-wider text-slate-500 dark:text-slate-400">
                    Related Threats Identified ({report.related_threats.length})
                  </div>
                  <div className="space-y-2">
                    {report.related_threats.map((rt, idx) => (
                      <div
                        key={idx}
                        className="p-3 rounded-lg bg-slate-50 dark:bg-cyber-elevated/40 border border-slate-200/60 dark:border-cyber-border/60 flex items-center justify-between text-xs"
                      >
                        <div>
                          <div className="font-semibold text-slate-900 dark:text-slate-100">{rt.threat}</div>
                          <div className="text-[11px] text-slate-500 dark:text-slate-400 font-mono">
                            {rt.confidence_label} ({Math.round(rt.confidence * 100)}%)
                          </div>
                        </div>
                        <Badge variant="severity" severity={rt.severity} size="sm" />
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Risk Score Widget */}
              <RiskMeter riskScore={report.risk_score} />
            </div>
          ) : (
            /* Empty prompt state */
            <div className="rounded-xl border border-dashed border-slate-200 dark:border-cyber-border p-8 text-center space-y-3 bg-white/50 dark:bg-cyber-surface/50">
              <div className="w-12 h-12 rounded-xl bg-slate-100 dark:bg-cyber-elevated text-slate-400 mx-auto flex items-center justify-center">
                <ShieldCheck className="w-6 h-6" />
              </div>
              <h3 className="text-sm font-semibold text-slate-800 dark:text-slate-200">
                Awaiting Incident Telemetry
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 max-w-xs mx-auto leading-relaxed">
                Select observed security facts on the left and click "Run Expert Analysis" to view deterministic conclusions and defense recommendations.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
