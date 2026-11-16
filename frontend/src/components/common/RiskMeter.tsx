import React from 'react';
import { SecurityRiskScore, RiskLevel } from '../../types';
import { ShieldAlert, ShieldCheck, AlertTriangle } from 'lucide-react';

interface RiskMeterProps {
  riskScore: SecurityRiskScore;
  compact?: boolean;
}

export const RiskMeter: React.FC<RiskMeterProps> = ({ riskScore, compact = false }) => {
  const { score, level, description, contributing_factors, category_breakdowns } = riskScore;

  const colorMap: Record<RiskLevel, { text: string; bg: string; border: string; bar: string }> = {
    Low: {
      text: 'text-emerald-500',
      bg: 'bg-emerald-500/10',
      border: 'border-emerald-500/20',
      bar: 'bg-emerald-500'
    },
    Moderate: {
      text: 'text-amber-500',
      bg: 'bg-amber-500/10',
      border: 'border-amber-500/20',
      bar: 'bg-amber-500'
    },
    High: {
      text: 'text-orange-500',
      bg: 'bg-orange-500/10',
      border: 'border-orange-500/20',
      bar: 'bg-orange-500'
    },
    Critical: {
      text: 'text-red-500',
      bg: 'bg-red-500/10',
      border: 'border-red-500/20',
      bar: 'bg-red-500'
    }
  };

  const currentColors = colorMap[level] || colorMap.Low;

  if (compact) {
    return (
      <div className="flex items-center space-x-3">
        <div className="relative w-12 h-12 flex items-center justify-center">
          <svg className="w-12 h-12 -rotate-90" viewBox="0 0 36 36">
            <path
              className="text-slate-200 dark:text-cyber-border stroke-current"
              strokeWidth="3.5"
              fill="none"
              d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
            />
            <path
              className={`${currentColors.text} stroke-current transition-all duration-700 ease-out`}
              strokeDasharray={`${score}, 100`}
              strokeWidth="3.5"
              strokeLinecap="round"
              fill="none"
              d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
            />
          </svg>
          <span className="absolute font-mono text-sm font-semibold">{score}</span>
        </div>
        <div>
          <div className="text-xs uppercase tracking-wider text-slate-500 dark:text-slate-400 font-mono">Risk Level</div>
          <div className={`text-sm font-semibold ${currentColors.text}`}>{level}</div>
        </div>
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-slate-200 dark:border-cyber-border bg-white dark:bg-cyber-surface p-6 shadow-sm">
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center space-x-2">
            <span className="text-xs uppercase tracking-wider font-mono text-slate-500 dark:text-slate-400">
              CyberMate Security Risk Score
            </span>
          </div>
          <h3 className="text-lg font-semibold text-slate-900 dark:text-slate-100 mt-1">
            Threat Posture Assessment
          </h3>
        </div>
        <div className={`px-3 py-1 rounded-full text-xs font-semibold uppercase tracking-wide font-mono border ${currentColors.bg} ${currentColors.text} ${currentColors.border}`}>
          {level} Risk
        </div>
      </div>

      <div className="mt-6 flex flex-col sm:flex-row items-center gap-6">
        {/* Sleek SVG Ring */}
        <div className="relative w-28 h-28 flex items-center justify-center shrink-0">
          <svg className="w-28 h-28 -rotate-90" viewBox="0 0 36 36">
            <path
              className="text-slate-100 dark:text-cyber-elevated stroke-current"
              strokeWidth="3"
              fill="none"
              d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
            />
            <path
              className={`${currentColors.text} stroke-current transition-all duration-1000 ease-out`}
              strokeDasharray={`${score}, 100`}
              strokeWidth="3"
              strokeLinecap="round"
              fill="none"
              d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
            />
          </svg>
          <div className="absolute text-center">
            <div className="text-3xl font-bold font-mono tracking-tight text-slate-900 dark:text-slate-100">
              {score}
            </div>
            <div className="text-[10px] uppercase font-mono text-slate-400">/ 100</div>
          </div>
        </div>

        {/* Score Context */}
        <div className="flex-1 space-y-2 text-center sm:text-left">
          <p className="text-sm text-slate-600 dark:text-slate-300 leading-relaxed">
            {description}
          </p>
          <div className="flex flex-wrap gap-2 pt-1">
            <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-100 dark:bg-cyber-elevated text-slate-600 dark:text-slate-400">
              0-25 Low
            </span>
            <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-100 dark:bg-cyber-elevated text-slate-600 dark:text-slate-400">
              26-50 Moderate
            </span>
            <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-100 dark:bg-cyber-elevated text-slate-600 dark:text-slate-400">
              51-75 High
            </span>
            <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-100 dark:bg-cyber-elevated text-slate-600 dark:text-slate-400">
              76-100 Critical
            </span>
          </div>
        </div>
      </div>

      {/* Category breakdown bars if available */}
      {category_breakdowns && category_breakdowns.length > 0 && (
        <div className="mt-6 pt-5 border-t border-slate-100 dark:border-cyber-border space-y-3">
          <div className="text-xs uppercase tracking-wider font-mono text-slate-500 dark:text-slate-400">
            Category Threat Breakdown
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {category_breakdowns.map((cat, idx) => (
              <div key={idx} className="bg-slate-50 dark:bg-cyber-elevated/40 rounded-lg p-2.5 border border-slate-200/60 dark:border-cyber-border/60">
                <div className="flex justify-between items-center text-xs mb-1.5">
                  <span className="font-medium text-slate-700 dark:text-slate-300">{cat.category}</span>
                  <span className="font-mono text-slate-500">{cat.score} pts</span>
                </div>
                <div className="w-full bg-slate-200 dark:bg-cyber-border h-1.5 rounded-full overflow-hidden">
                  <div
                    className={`h-full ${cat.score > 25 ? 'bg-red-500' : cat.score > 15 ? 'bg-orange-500' : 'bg-emerald-500'} rounded-full transition-all duration-500`}
                    style={{ width: `${Math.min(100, (cat.score / 35) * 100)}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Contributing Factors */}
      {contributing_factors && contributing_factors.length > 0 && (
        <div className="mt-5 pt-4 border-t border-slate-100 dark:border-cyber-border">
          <div className="text-xs uppercase tracking-wider font-mono text-slate-500 dark:text-slate-400 mb-2">
            Primary Contributing Factors
          </div>
          <ul className="space-y-1.5 text-xs text-slate-600 dark:text-slate-300">
            {contributing_factors.slice(0, 4).map((f, i) => (
              <li key={i} className="flex items-start space-x-2">
                <span className="text-slate-400">•</span>
                <span>{f}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
};
