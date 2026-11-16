import React, { useState, useEffect } from 'react';
import {
  Gauge,
  ShieldAlert,
  RotateCcw,
  CheckCircle2,
  AlertTriangle,
  Info,
  Sliders,
  ChevronRight
} from 'lucide-react';
import { api } from '../services/api';
import { SecurityRiskScore } from '../types';
import { RiskMeter } from '../components/common/RiskMeter';

export const RiskScorePage: React.FC = () => {
  // Pre-configured selectable risk indicator questions
  const [selectedFactors, setSelectedFactors] = useState<Record<string, boolean>>({
    antivirus_disabled: false,
    mfa_disabled: false,
    failed_logins_high: false,
    unknown_ip_access: false,
    large_data_transfer: false,
    shadow_copy_deleted: false,
    unknown_process: false,
    public_bucket_exposure: false,
    phishing_link_clicked: false,
    suspicious_port_scan: false,
    mass_file_deletion: false,
    obfuscated_script: false
  });

  const [riskScore, setRiskScore] = useState<SecurityRiskScore | null>(null);
  const [calculating, setCalculating] = useState(false);

  const factorDefinitions = [
    { id: 'antivirus_disabled', label: 'Antivirus or EDR sensor disabled / killed', domain: 'Endpoint', weight: 15 },
    { id: 'mfa_disabled', label: 'MFA deactivated or push notification flooded', domain: 'Authentication', weight: 15 },
    { id: 'failed_logins_high', label: 'More than 10 consecutive failed login attempts', domain: 'Authentication', weight: 12 },
    { id: 'unknown_ip_access', label: 'Successful access from unrecognized external IP', domain: 'Authentication', weight: 10 },
    { id: 'shadow_copy_deleted', label: 'Volume shadow copies deleted (vssadmin delete shadows)', domain: 'System', weight: 20 },
    { id: 'unknown_process', label: 'Unsigned process consuming abnormal CPU/RAM', domain: 'System', weight: 10 },
    { id: 'large_data_transfer', label: 'Gigabytes of outbound network traffic to untrusted IP', domain: 'Network', weight: 15 },
    { id: 'suspicious_port_scan', label: 'Internal port scan probing admin ports (SSH/RDP/SMB)', domain: 'Network', weight: 10 },
    { id: 'public_bucket_exposure', label: 'Cloud storage bucket policy modified to public access', domain: 'Cloud', weight: 18 },
    { id: 'phishing_link_clicked', label: 'User clicked deceptive link in lookalike email', domain: 'Email', weight: 10 },
    { id: 'mass_file_deletion', label: 'Mass file or database table drops by privileged account', domain: 'Insider', weight: 20 },
    { id: 'obfuscated_script', label: 'PowerShell executed with -EncodedCommand or base64', domain: 'System', weight: 12 }
  ];

  const handleToggle = (id: string) => {
    setSelectedFactors((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const handleReset = () => {
    const resetObj: Record<string, boolean> = {};
    Object.keys(selectedFactors).forEach((k) => (resetObj[k] = false));
    setSelectedFactors(resetObj);
  };

  useEffect(() => {
    async function evaluateScore() {
      setCalculating(true);
      // Map to facts
      const facts: Record<string, any> = {
        antivirus_disabled: selectedFactors.antivirus_disabled,
        mfa_disabled: selectedFactors.mfa_disabled,
        failed_login_count: selectedFactors.failed_logins_high ? 15 : 0,
        login_from_unknown_ip: selectedFactors.unknown_ip_access,
        successful_login_after_failures: selectedFactors.unknown_ip_access && selectedFactors.failed_logins_high,
        shadow_copy_deleted: selectedFactors.shadow_copy_deleted,
        unknown_process: selectedFactors.unknown_process,
        high_cpu_usage: selectedFactors.unknown_process,
        large_data_transfer: selectedFactors.large_data_transfer,
        unknown_external_ip: selectedFactors.large_data_transfer,
        suspicious_port_activity: selectedFactors.suspicious_port_scan,
        public_bucket_exposure: selectedFactors.public_bucket_exposure,
        phishing_indicators: selectedFactors.phishing_link_clicked,
        mass_file_deletion: selectedFactors.mass_file_deletion,
        obfuscated_powershell: selectedFactors.obfuscated_script
      };

      try {
        const score = await api.calculateRiskScore(facts);
        setRiskScore(score);
      } catch (err) {
        console.error('Failed to calculate risk score:', err);
      } finally {
        setCalculating(false);
      }
    }
    evaluateScore();
  }, [selectedFactors]);

  const activeCount = Object.values(selectedFactors).filter(Boolean).length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold tracking-tight text-slate-900 dark:text-white">
          CyberMate Risk Scoring Engine
        </h2>
        <p className="text-sm text-slate-600 dark:text-slate-300 mt-1">
          A transparent, deterministic risk assessment model. Toggling observable indicators adjusts score weights across authentication, endpoint, system, network, and cloud domains.
        </p>
      </div>

      {/* Main Layout Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Factors Selector (7 cols) */}
        <div className="lg:col-span-7 space-y-4">
          <div className="rounded-xl border border-slate-200 dark:border-cyber-border bg-white dark:bg-cyber-surface p-5 sm:p-6 shadow-sm space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-100 dark:border-cyber-border">
              <div>
                <h3 className="font-semibold text-sm text-slate-900 dark:text-slate-100">
                  Observable Risk Indicators
                </h3>
                <p className="text-xs text-slate-500">
                  Toggle observations observed in your environment
                </p>
              </div>
              <button
                onClick={handleReset}
                type="button"
                className="inline-flex items-center space-x-1.5 px-2.5 py-1.5 text-xs font-medium rounded-lg border border-slate-200 dark:border-cyber-border text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100 transition-colors"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>Clear All</span>
              </button>
            </div>

            <div className="space-y-2">
              {factorDefinitions.map((f) => {
                const isChecked = selectedFactors[f.id];
                return (
                  <div
                    key={f.id}
                    onClick={() => handleToggle(f.id)}
                    className={`p-3 rounded-lg border cursor-pointer transition-all flex items-center justify-between gap-3 ${
                      isChecked
                        ? 'bg-emerald-500/5 dark:bg-emerald-950/20 border-emerald-500/30'
                        : 'bg-slate-50/60 dark:bg-cyber-elevated/40 border-slate-200/70 dark:border-cyber-border/70 hover:border-slate-300'
                    }`}
                  >
                    <div className="space-y-0.5">
                      <div className="text-xs font-medium text-slate-900 dark:text-slate-100">
                        {f.label}
                      </div>
                      <div className="flex items-center space-x-2 text-[11px] font-mono text-slate-500 dark:text-slate-400">
                        <span>Layer: {f.domain}</span>
                        <span>•</span>
                        <span>Impact: +{f.weight} pts</span>
                      </div>
                    </div>

                    <input
                      type="checkbox"
                      checked={isChecked}
                      onChange={() => {}} // handled by parent onClick
                      className="w-4 h-4 text-emerald-600 rounded border-slate-300 focus:ring-emerald-500 shrink-0"
                    />
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Live Risk Meter & Action Plan (5 cols) */}
        <div className="lg:col-span-5 space-y-6">
          {riskScore ? (
            <>
              <RiskMeter riskScore={riskScore} />

              {/* Urgent Mitigation Actions */}
              {riskScore.urgent_actions && riskScore.urgent_actions.length > 0 && (
                <div className="rounded-xl border border-slate-200 dark:border-cyber-border bg-white dark:bg-cyber-surface p-5 shadow-sm space-y-3">
                  <div className="flex items-center space-x-2 text-xs font-mono uppercase tracking-wider text-slate-500 dark:text-slate-400">
                    <ShieldAlert className="w-4 h-4 text-emerald-500" />
                    <span>Prioritized Defense Roadmap</span>
                  </div>

                  <ol className="space-y-2 text-xs text-slate-700 dark:text-slate-300">
                    {riskScore.urgent_actions.map((act, idx) => (
                      <li key={idx} className="flex items-start space-x-2">
                        <span className="w-4 h-4 rounded-full bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 font-mono text-[10px] flex items-center justify-center shrink-0 mt-0.5 font-bold">
                          {idx + 1}
                        </span>
                        <span>{act}</span>
                      </li>
                    ))}
                  </ol>
                </div>
              )}

              {/* Methodology note */}
              <div className="p-4 rounded-xl bg-slate-50 dark:bg-cyber-elevated/40 border border-slate-200/60 dark:border-cyber-border/60 text-xs text-slate-500 dark:text-slate-400 space-y-1.5 leading-relaxed">
                <div className="flex items-center space-x-1.5 font-mono text-[11px] text-slate-600 dark:text-slate-300 font-semibold">
                  <Info className="w-3.5 h-3.5 text-emerald-500" />
                  <span>Transparent Scoring Methodology</span>
                </div>
                <p>
                  CyberMate's risk score combines rule severity floors (Critical: 65-100, High: 45-75, Moderate: 26-50, Low: 0-25) with specific telemetry multipliers. It is intended as an operational defensive indicator, not an empirical actuarial metric.
                </p>
              </div>
            </>
          ) : (
            <div className="p-12 text-center rounded-xl border border-slate-200 dark:border-cyber-border bg-white dark:bg-cyber-surface animate-pulse" />
          )}
        </div>
      </div>
    </div>
  );
};
