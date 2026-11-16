import React from 'react';
import { SeverityLevel, RiskLevel } from '../../types';

interface BadgeProps {
  children?: React.ReactNode;
  variant?: 'severity' | 'risk' | 'category' | 'neutral' | 'accent';
  severity?: SeverityLevel;
  risk?: RiskLevel;
  size?: 'sm' | 'md';
  className?: string;
}

export const Badge: React.FC<BadgeProps> = ({
  children,
  variant = 'neutral',
  severity,
  risk,
  size = 'md',
  className = ''
}) => {
  const sizeClasses = size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-2.5 py-1 text-xs';

  if (variant === 'severity' && severity) {
    const sevStyles = {
      LOW: 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20',
      MEDIUM: 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/20',
      HIGH: 'bg-orange-500/10 text-orange-600 dark:text-orange-400 border border-orange-500/20',
      CRITICAL: 'bg-red-500/10 text-red-600 dark:text-red-400 border border-red-500/20 font-semibold',
    }[severity];

    return (
      <span className={`inline-flex items-center rounded-md font-mono uppercase tracking-wide ${sevStyles} ${sizeClasses} ${className}`}>
        {children || severity}
      </span>
    );
  }

  if (variant === 'risk' && risk) {
    const riskStyles = {
      Low: 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20',
      Moderate: 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/20',
      High: 'bg-orange-500/10 text-orange-600 dark:text-orange-400 border border-orange-500/20',
      Critical: 'bg-red-500/10 text-red-600 dark:text-red-400 border border-red-500/20 font-semibold',
    }[risk];

    return (
      <span className={`inline-flex items-center rounded-md font-medium ${riskStyles} ${sizeClasses} ${className}`}>
        {children || risk}
      </span>
    );
  }

  if (variant === 'category') {
    return (
      <span className={`inline-flex items-center rounded-md bg-slate-100 dark:bg-cyber-elevated text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-cyber-border font-medium ${sizeClasses} ${className}`}>
        {children}
      </span>
    );
  }

  if (variant === 'accent') {
    return (
      <span className={`inline-flex items-center rounded-md bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-800/40 font-medium ${sizeClasses} ${className}`}>
        {children}
      </span>
    );
  }

  return (
    <span className={`inline-flex items-center rounded-md bg-slate-100 dark:bg-cyber-surface text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-cyber-border ${sizeClasses} ${className}`}>
      {children}
    </span>
  );
};
