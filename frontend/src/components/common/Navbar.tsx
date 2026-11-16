import React from 'react';
import { Menu, ShieldAlert, Sparkles, Terminal } from 'lucide-react';
import { ThemeToggle } from './ThemeToggle';
import { PageId } from './Sidebar';

interface NavbarProps {
  currentPage: PageId;
  onOpenMobile: () => void;
  onSelectPage: (page: PageId) => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  currentPage,
  onOpenMobile,
  onSelectPage
}) => {
  const pageTitles: Record<PageId, { title: string; subtitle: string }> = {
    dashboard: {
      title: 'Security Operations Dashboard',
      subtitle: 'Defensive Security Intelligence & Diagnosis'
    },
    analyze: {
      title: 'Analyze Incident',
      subtitle: 'Deterministic rule-based threat evaluation from security observations'
    },
    chat: {
      title: 'Chat Diagnosis',
      subtitle: 'Conversational assistant with automated fact extraction & expert reasoning'
    },
    threats: {
      title: 'Threat Library',
      subtitle: 'Catalog of threat profiles, MITRE ATT&CK vectors, and defense actions'
    },
    scenarios: {
      title: 'Attack Scenarios',
      subtitle: 'Safe educational simulations testing expert-system diagnosis'
    },
    risk: {
      title: 'CyberMate Risk Score',
      subtitle: 'Transparent deterministic risk assessment across critical domains'
    },
    password: {
      title: 'Password Generator',
      subtitle: 'Cryptographically secure randomness with zero-storage guarantee'
    },
    history: {
      title: 'Incident History',
      subtitle: 'Local audit trail of analyzed incidents and threat records'
    },
    about: {
      title: 'About / System Architecture',
      subtitle: 'Expert system principles, rule pipeline, and future roadmap'
    }
  };

  const current = pageTitles[currentPage] || pageTitles.dashboard;

  return (
    <header className="h-16 px-4 lg:px-8 bg-white dark:bg-cyber-surface border-b border-slate-200 dark:border-cyber-border flex items-center justify-between sticky top-0 z-30 transition-colors">
      <div className="flex items-center space-x-3">
        {/* Mobile menu trigger */}
        <button
          onClick={onOpenMobile}
          className="p-2 rounded-lg text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-cyber-elevated lg:hidden"
          aria-label="Open navigation menu"
        >
          <Menu className="w-5 h-5" />
        </button>

        <div>
          <h1 className="text-sm lg:text-base font-semibold text-slate-900 dark:text-slate-100 flex items-center gap-2">
            <span>{current.title}</span>
          </h1>
          <p className="hidden sm:block text-xs text-slate-500 dark:text-slate-400">
            {current.subtitle}
          </p>
        </div>
      </div>

      <div className="flex items-center space-x-3">
        {currentPage !== 'analyze' && (
          <button
            onClick={() => onSelectPage('analyze')}
            className="hidden sm:inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-emerald-600 hover:bg-emerald-500 text-white shadow-sm transition-all"
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            <span>Analyze Incident</span>
          </button>
        )}

        <ThemeToggle />
      </div>
    </header>
  );
};
